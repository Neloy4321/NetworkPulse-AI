"""Local-only portfolio acceptance contract: no real IDS quality claim."""

from pathlib import Path

from scripts.local_portfolio_acceptance import run_acceptance


def test_isolated_local_portfolio_demo_passes_without_production_promotion():
    report = run_acceptance()
    assert report["scope"] == "LOCAL_SYNTHETIC_PORTFOLIO_DEMO"
    assert report["local_demo_engineering"] == "PASS"
    assert report["independent_ml_generalization"] == "NOT_ACCEPTED"
    assert report["production_or_live_network_acceptance"] == "NOT_ACCEPTED"
    assert len(report["synthetic_model_sha256"]) == 64
    assert len(report["checks"]) >= 8
    assert all(value == "PASS" for value in report["checks"].values())


def test_report_source_preserves_independent_failure_notice():
    source = (
        Path(__file__).resolve().parents[1]
        / "scripts" / "local_portfolio_acceptance.py"
    ).read_text(encoding="utf-8")
    assert "Previous independent-source recall failure is not waived" in source
    assert '"NOT_ACCEPTED"' in source
