"""Real UNSW-NB15 capture replay through authenticated NetworkPulse API.

The data is a private, ephemeral CI download; never persist/archive flow rows,
IP addresses, JWTs, generated RSA keys, SQLite DB or trained model artifacts.
This tests real flow ingestion and JWT/RBAC, NOT real external IdP or TLS.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.config import Settings
from networkpulse.detector import train
from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.evaluation.unsw import _hash_file
from networkpulse.migrations import upgrade_database

SOURCE_SHA256 = "3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a"
SOURCE_BYTES = 586382286
ISSUER = "https://ci-idp.example.invalid"
AUDIENCE = "networkpulse-api"


def replay(archive: Path) -> dict:
    if archive.stat().st_size != SOURCE_BYTES:
        raise ValueError("UNSW-NB15 source length changed; refuse replay")
    digest = _hash_file(archive)
    if digest != SOURCE_SHA256:
        raise ValueError("UNSW-NB15 source checksum changed; refuse replay")

    with zipfile.ZipFile(archive) as zf:
        earlier, earlier_info = read_reservoir(zf, "UNSW-NB15_1.csv", 2200, 42)
        later, later_info = read_reservoir(zf, "UNSW-NB15_4.csv", 1300, 43)

    training = list({event.key(): event for event in earlier}.values())
    heldout = {event.key(): event for event in later}
    for event in training:
        heldout.pop(event.key(), None)
    candidate_events = list(heldout.values())
    if len(training) < 1000 or len(candidate_events) < 100:
        raise ValueError("Too few independent real capture flows")
    if max(e.timestamp for e in training) >= min(e.timestamp for e in candidate_events):
        raise ValueError("Real capture train and test windows overlap")
    if len({e.label for e in candidate_events}) != 2:
        raise ValueError("Held-out capture lacks benign/attack labels")
    # The API receives only original later-capture events; it never trains
    # or calibrates on them. Smaller replay keeps CI API state bounded.
    replay_events = candidate_events[:50]
    model = train(training, seed=42, source="unsw_raw_real_capture_security_replay")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    now = int(time.time())

    def authorization(role: str, *, aud: str = AUDIENCE) -> dict[str, str]:
        signed = jwt.encode(
            {"iss": ISSUER, "aud": aud, "sub": "ci-" + role, "iat": now,
             "exp": now + 600, "networkpulse_role": role},
            private_key, algorithm="RS256",
        )
        return {"Authorization": "Bearer " + signed}

    with tempfile.TemporaryDirectory(prefix="networkpulse-unsw-auth-") as td:
        directory = Path(td)
        model_file = directory / "private-model.joblib"
        database = "sqlite:///" + str(directory / "private.db")
        model.save(model_file)
        upgrade_database(database)
        settings = Settings(
            database_url=database,
            model_path=model_file,
            api_key="ci-private-only-unused-in-oidc",
            auth_mode="oidc",
            oidc_issuer=ISSUER,
            oidc_audience=AUDIENCE,
            oidc_jwks_url=ISSUER + "/jwks",
        )
        # Real RS256 signature/claims verification, with local signing key in
        # place of a live external JWKS server. No credentials are exported.
        fake_jwks = SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=public_key)
        )
        with patch("jwt.PyJWKClient", return_value=fake_jwks):
            with TestClient(create_app(settings)) as api:
                payload = {"events": [e.model_dump(mode="json") for e in replay_events]}
                assert api.get("/api/v1/summary").status_code == 401
                assert api.get("/api/v1/summary",
                               headers=authorization("viewer", aud="wrong")).status_code == 401
                assert api.get("/api/v1/summary",
                               headers=authorization("viewer")).status_code == 200
                assert api.post("/api/v1/ingest", json=payload).status_code == 401
                assert api.post("/api/v1/ingest", json=payload,
                                headers=authorization("viewer")).status_code == 403
                response = api.post("/api/v1/ingest", json=payload,
                                    headers=authorization("analyst"))
                assert response.status_code == 200, "Authorized real flow replay failed"
                first = response.json()
                assert first["received"] == len(replay_events)
                assert first["inserted"] == len(replay_events)
                repeated = api.post("/api/v1/ingest", json=payload,
                                    headers=authorization("analyst"))
                assert repeated.status_code == 200
                assert repeated.json()["inserted"] == 0
                assert repeated.json()["duplicates"] == len(replay_events)
                visible = api.get("/api/v1/summary", headers=authorization("viewer"))
                assert visible.status_code == 200
                assert visible.json()["flows"] == len(replay_events)
                assert api.get("/metrics", headers=authorization("viewer")).status_code == 403
                assert api.get("/metrics", headers=authorization("admin")).status_code == 200
                # Exact production behavior query over real held-out captured
                # flow records, not a synthetic mock of its SQL implementation.
                end_time = max(flow.timestamp for flow in replay_events)
                behavior_response = api.get(
                    "/api/v1/intelligence/behavior",
                    params={"window_minutes": 5, "lookback_minutes": 1440,
                            "until": end_time.isoformat(), "limit": 100},
                    headers=authorization("viewer"),
                )
                assert behavior_response.status_code == 200
                behavior = behavior_response.json()
                assert not behavior["has_more"]
                assert sum(w["flow_count"] for w in behavior["windows"]) == len(replay_events)
                assert all(w["distinct_destination_ports"] > 0 for w in behavior["windows"])
                assert all(w["distinct_destination_hosts"] > 0 for w in behavior["windows"])
                assert api.get("/api/v1/intelligence/behavior").status_code == 401
                assert api.get("/api/v1/intelligence/behavior",
                               params={"window_minutes": 2},
                               headers=authorization("viewer")).status_code == 422

    # Privacy contract: aggregate only. Never put IPs/rows/tokens in output.
    return {
        "dataset": "Original raw UNSW-NB15 (user-authorized Drive archive)",
        "dataset_archive_sha256": digest,
        "training_capture": "UNSW-NB15_1.csv",
        "heldout_capture": "UNSW-NB15_4.csv",
        "train_unique_rows": len(training),
        "heldout_unique_rows": len(candidate_events),
        "replayed_real_flows": len(replay_events),
        "inserted_real_flows": first["inserted"],
        "operational_behavior_windows": len(behavior["windows"]),
        "repeat_duplicates": repeated.json()["duplicates"],
        "alerts_created": first["alerts_created"],
        "validation": {
            "real_capture_chronological_separation": True,
            "rs256_signature_issuer_audience_verified": True,
            "unauthenticated_read_denied": True,
            "viewer_read_allowed": True,
            "viewer_mutation_denied": True,
            "analyst_real_data_ingest_allowed": True,
            "unauthenticated_ingest_denied": True,
            "admin_metrics_allowed": True,
            "viewer_metrics_denied": True,
            "replay_idempotent": True,
            "operational_behavior_api_real_flows": True,
            "real_behavior_counts_match_ingest": True,
        },
        "limitations": [
            "OIDC/JWKS issuer was replaced with locally generated test keys, not real IdP",
            "No public HTTPS or Caddy gateway tested",
            "No Redis-backed browser session or multiple-worker validation",
            "Same original cyber range, not independent field network",
            "Not a standalone model accuracy evaluation or production deployment",
        ],
        "full_capture_valid_counts": {
            "earlier": earlier_info["valid_rows"],
            "later": later_info["valid_rows"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = replay(arguments.zip)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "dataset_archive_sha256": report["dataset_archive_sha256"],
        "replayed_real_flows": report["replayed_real_flows"],
        "validation": report["validation"],
        "limitations": report["limitations"],
    }, indent=2))


if __name__ == "__main__":
    main()
