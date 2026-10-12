# Architecture & Engineering Decisions

## High-level system

```mermaid
flowchart LR
  Z[Zeek JSON conn.log] --> A[Adapters]
  S[Suricata EVE flow] --> A
  C[Canonical JSONL] --> A
  G[Seeded simulator] --> A
  A --> V[Pydantic validation]
  V --> F[Versioned feature transform]
  F --> D[Isolation Forest + calibrated threshold]
  D --> P[Idempotent persistence]
  P --> E[(SQLAlchemy SQLite or PostgreSQL)]
  P --> T[Alert + severity + signal clues]
  T --> E
  E --> API[FastAPI]
  API --> UI[Responsive web console]
  API --> R[Human triage + audit trail]
  R --> E
```

## Design boundary: flow metadata, not packets

No packet payloads, credentials, PCAP decoding, capture daemon, or packet injection. Input consists of summarized connections: IPs, ports, direction-dependent counters, duration, protocol and state. The project accepts logs from your own network or authorized datasets only.

## Ingestion and idempotency

1. Each connector transforms an external JSON object into a strict `FlowEvent` schema.
2. Timestamp is normalized to UTC; IPs and unsigned counters are validated.
3. `key()` hashes the canonical serialized event, excluding only evaluation labels.
4. The service scores canonical flows, then lets the database arbitrate duplicates using SQLite/PostgreSQL `INSERT ... ON CONFLICT DO NOTHING ... RETURNING`.
5. Bounded-batch flow inserts and matching anomaly alerts commit **in one transaction**, or roll back together. A second ingestion attempt cannot insert the same event ID or alert twice under tested conditions.

**Current limitation:** The SQLite thread-level concurrency regression test confirms duplicate insertion protection; PostgreSQL multi-worker throughput and contention behavior still need dedicated integration/load tests. The system is not an external exactly-once delivery queue.

## Model lifecycle

```mermaid
flowchart TD
 A[Chronological canonical records] --> B[60% fit window]
 A --> C[15% calibration window]
 A --> D[25% untouched evaluation]
 B --> E[Benign-only feature fitting]
 E --> F[DictVectorizer + Isolation Forest]
 C --> G[Benign-only threshold quantile]
 F --> G
 G --> H[Detector artifact, versioned features]
 H --> I[Score later flows]
 D --> J[Held-out metrics]
 H --> J
```

- **Anomaly score:** negative Isolation Forest decision function (larger means more unusual).
- **Threshold:** 97th percentile of independent benign calibration scores (configurable at training).
- **Relative risk:** a clipped linear mapping around this threshold to 0–100. Not a posterior probability and not independently calibrated to incident severity.
- **Explanation reasons:** interpretable rule-based *signals* attached to a flow (e.g., no response packets). They are **not SHAP attributions** or causal explanations of the Isolation Forest decision.
- **Artifact loading:** joblib uses pickle; only locally generated/trusted artifacts may be loaded.

## API and security

The browser and API share an origin; no permissive CORS rule is added. Mutating operations require `X-API-Key` and compare in constant time. The browser prompts for the key during triage and never writes it to local storage. Read-only endpoints are unauthenticated for local exploration. In production, isolate the app behind a trusted reverse proxy, TLS and stronger identity control.

## Persistence schema

```mermaid
erDiagram
    NETWORK_EVENTS ||--o| ALERTS : "has anomaly alert"
    ALERTS ||--o{ ALERT_AUDIT : "records transitions"
    NETWORK_EVENTS {
        string id PK
        timestamp timestamp
        string src_ip
        string dst_ip
        float anomaly_score
        int risk
        bool anomalous
    }
    ALERTS {
        int id PK
        string event_id FK
        string severity
        string status
        json reasons
    }
    ALERT_AUDIT {
        int id PK
        int alert_id FK
        string old_status
        string new_status
        string note
    }
```

## Deployment approaches

- **Fastest run:** Python + SQLite + local file artifact.
- **Compose:** Python API service + PostgreSQL 16 + model/data volume.
- **Database schema:** Alembic revisions and conflict-safe writes are implemented, with a tested SQLite backup/legacy migration path. PostgreSQL integration and restore drills remain pending.
- **Cloud readiness:** This repo is still a demonstrable baseline; SSO, hosted telemetry integration, rate limiting, retention automation and real deployment verification remain to be implemented.
