from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from networkpulse.api import create_app
from networkpulse.config import Settings
from networkpulse.detector import train
from networkpulse.simulator import sample_flows


@pytest.fixture(scope="session")
def trained_detector():
    return train(sample_flows(310, seed=15), seed=15)


@pytest.fixture
def app_settings(tmp_path: Path, trained_detector):
    model_file = tmp_path / "model.joblib"
    trained_detector.save(model_file)
    return Settings(
        database_url="sqlite:///" + str(tmp_path / "networkpulse.db"),
        model_path=model_file,
        api_key="local-test-api-key-strong-123",
    )


@pytest.fixture
def client(app_settings):
    with TestClient(create_app(app_settings)) as api:
        yield api


@pytest.fixture
def samples():
    return sample_flows(310, seed=15)
