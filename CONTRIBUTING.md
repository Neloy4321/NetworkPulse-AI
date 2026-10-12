# Contributing

Thank you for helping improve NetworkPulse AI. The priority is correctness, reproducibility, clear scope and secure handling of telemetry.

## Development loop

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check networkpulse tests
python -m compileall -q networkpulse
```

Include tests when changing adapters, features, schema, scoring or audit behavior. Preserve strict time boundaries between training, calibration and test data. Avoid introducing raw packet payloads, sensitive logs, hard-coded secrets or unverified claims of accuracy/production readiness.

PRs should summarize the purpose, changed files, sample output and limitations. Changes to model features must update `FEATURE_VERSION`, training metadata and the model card.
