import pytest

from networkpulse.config import Settings
from networkpulse.detector import train
from networkpulse.service import severity


def test_severity_thresholds():
    assert severity(90) == "critical"
    assert severity(80) == "high"
    assert severity(65) == "medium"
    assert severity(50) == "low"


def test_config_rejects_short_secret(monkeypatch):
    monkeypatch.setenv("NETWORKPULSE_API_KEY", "short")
    with pytest.raises(ValueError, match="at least 16"):
        Settings.from_env()
