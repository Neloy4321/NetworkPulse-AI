# NetworkPulse-AI — Local Portfolio Demo Acceptance

**Scope:** single-user, loopback-only, offline demonstration with seeded synthetic flows.
**Decision:** local *engineering* demo may be accepted after the smoke check prints
`"local_demo_engineering": "PASS"`. This is **not ML detection-quality acceptance**,
not a certificate, and not approval for production or live-network security decisions.

## Acceptance gates (kept separate deliberately)

| Gate | Acceptance rule | Current evidence |
| --- | --- | --- |
| Local engineering demo | Disposable SQLite migration, synthetic model creation, repeat bootstrap idempotence, model source, API liveness/readiness, locally served dashboard/static JS, unauthorized-write rejection, authenticated inference/ingestion and persisted summary all pass | Run `scripts/local_portfolio_acceptance.py`; preserve its output |
| On your Windows laptop | The same script passes in your own virtual environment, and you can open the dashboard at `127.0.0.1:8000` | **Pending operator execution** until you actually run it |
| Independent real-dataset generalization | New, disjoint, meaningful multi-day holdout meets predeclared recall/FPR lower/upper Wilson thresholds | **NO-GO**: prior fixed UWF-Zeek external stress demonstrated only ~17.93% attack recall |
| Signed real deployment / live sensors | Real approved model, reviewer and sensor evidence | **NOT TESTED / NOT REQUIRED for this local demo** |

Do not treat localhost access, successful tests, or synthetic holdout statistics as proof
of intrusion-detection effectiveness. There is no exception to the data-quality failure.

## One-command isolated demo acceptance check

Prerequisite: Python 3.11–3.13 and project installed with `python -m pip install -e ".[dev]"`.

Windows PowerShell (from repository root):

```powershell
$stamp = Get-Date -Format yyyyMMdd-HHmmss
python scripts/local_portfolio_acceptance.py --report "reports/local-demo-$stamp.json"
```

Linux/macOS:

```bash
python scripts/local_portfolio_acceptance.py
```

The command intentionally creates a **temporary SQLite database and temporary
synthetic-only model**. It never overwrites `data/model.joblib`, your normal database,
research artifacts, signed candidates or thresholds. After the smoke test, temporary
data is deleted. The optional JSON report contains only gate results, Python and git
revision, time and synthetic-model SHA256—not network endpoints, passwords or API keys.
Existing report filenames are never overwritten. A nonzero exit code or `FAIL` is not
an acceptance.

The smoke test uses an in-process FastAPI client; it **does not establish** that a
physical browser, actual Windows installer, real Zeek/Suricata stream, OIDC, TLS or cloud
deployment was tested. Complete the human local dashboard check separately.

## Open the actual localhost portfolio dashboard

After installing dependencies, use a fresh development key and your own local database.
Do not point these commands at production data.

```powershell
$env:NETWORKPULSE_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
networkpulse db upgrade
networkpulse bootstrap
uvicorn networkpulse.api:create_app --factory --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** from that same computer. Verify the Overview, Traffic,
Investigations and Model tabs, then shut down with Ctrl+C. Never run the demo on
`0.0.0.0`, forward its port to the public internet, or enable automatic blocking.

## CI evidence and limits

The dedicated `Local portfolio acceptance` workflow runs the same script and its
contract tests on GitHub Actions and uploads the aggregate JSON report. Existing
`Quality gates` remains the comprehensive regression suite. Treat the Actions run's
actual conclusion as the source of truth; workflow definitions alone are not a PASS.

An Actions PASS shows reproducibility on a GitHub runner, **not successful execution on
Neloy's Windows laptop**. The Windows step above is the remaining user-operated proof.

## Honest portfolio wording

> **NetworkPulse-AI** — An advanced local network-flow observability and ML-assisted
> anomaly triage project with Zeek/Suricata adapters, SQLite/PostgreSQL storage,
> a FastAPI dashboard, synthetic-demo acceptance checks, CI tests and reproducible
> independent-dataset research. The local engineering workflow is testable; external
> intrusion-detection generalization remains an open limitation.

**Do not write:** "production-ready NIDS", "fully validated detection accuracy",
"99.9% generalization recall", "deployed real-time threat prevention", or "ML acceptance
PASS" without the corresponding independent evidence.

See the original [README](../README.md), [model card](MODEL_CARD.md) and
[external results](REAL_DATA_RESULTS.md) for fuller evidence and limitations.
