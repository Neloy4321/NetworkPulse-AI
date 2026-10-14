"""Never accept documented example credentials as operational local secrets."""
import pytest

from networkpulse.config import Settings


@pytest.mark.parametrize("key", [
    "change-this-demo-key-at-least-24-chars",
    "replace-me-with-a-strong-key",
    "your-secret-goes-here",
    "  a-valid-looking-long-key  ",
])
def test_known_placeholder_local_keys_are_rejected(monkeypatch, key):
    monkeypatch.setenv("NETWORKPULSE_API_KEY", key)
    monkeypatch.setenv("NETWORKPULSE_AUTH_MODE", "local")
    with pytest.raises(ValueError, match="placeholder or padded"):
        Settings.from_env()


def test_non_placeholder_local_key_remains_supported(monkeypatch):
    monkeypatch.setenv("NETWORKPULSE_API_KEY", "s3cure-example-locally-set-123")
    monkeypatch.setenv("NETWORKPULSE_AUTH_MODE", "local")
    assert Settings.from_env().api_key == "s3cure-example-locally-set-123"
