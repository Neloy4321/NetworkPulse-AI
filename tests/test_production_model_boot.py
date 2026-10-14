"""Production startup must never generate synthetic flow models implicitly."""
from pathlib import Path


def test_production_image_never_bootstraps_synthetic_model():
    docker = Path("Dockerfile").read_text()
    assert 'NETWORKPULSE_DEPLOYMENT:-development' in docker
    assert 'Production requires a prevalidated model' in docker
    assert 'Production requires MODEL_SHA256' in docker
    assert 'else python -m networkpulse.cli bootstrap' in docker


def test_compose_requires_prevalidated_model_sha():
    overlay = Path("compose.tls.yaml").read_text()
    assert 'MODEL_SHA256: ${MODEL_SHA256:?' in overlay
