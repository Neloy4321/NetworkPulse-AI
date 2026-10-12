# Security Policy

## Intended use

NetworkPulse AI is an educational and research-oriented **defensive telemetry analysis** platform. Use only network flow data you are authorized to process. No packet payloads, scanning, blocking or active intrusion tooling is included.

## Reporting security issues

Please avoid posting exploit details or credentials in public GitHub Issues. Contact the project owner at **neloybbs@gmail.com** with the affected version, a minimal reproduction and impact summary. This repository does not provide a security disclosure SLA.

## Deployment boundary

The demonstration is intentionally local. The dashboard's read-only endpoints are unauthenticated. Do **not** expose it on the public internet without authentication, TLS, rate limiting, privacy review, secrets management and operational safeguards.

## Data integrity and privacy

Only use authorized logs, avoid collecting packet payloads, apply retention limits, avoid committing `.env`/database/model artifacts, and do not load third-party joblib/pickle artifacts.
