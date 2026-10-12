import json

from networkpulse.cli import main


def test_generate_demo_and_train(tmp_path, capsys):
    out = tmp_path / "synthetic.jsonl"
    mdl = tmp_path / "trained.joblib"
    assert main(["generate-demo", "--count", "140", "--seed", "11", "--output", str(out)]) == 0
    events = [json.loads(x) for x in out.read_text().splitlines()]
    assert len(events) == 140
    assert any(x["label"] == "anomaly" for x in events)
    assert main(["train", "--data", str(out), "--model", str(mdl), "--seed", "11"]) == 0
    assert mdl.exists()
    assert '"metrics"' in capsys.readouterr().out


def test_bootstrap_idempotency(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NETWORKPULSE_API_KEY", "test-strong-key-for-bootstrap")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "np.db"))
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "np.joblib"))
    assert main(["bootstrap", "--count", "160", "--seed", "7"]) == 0
    a = capsys.readouterr().out
    assert '"inserted": 40' in a
    assert main(["bootstrap", "--count", "160", "--seed", "7"]) == 0
    b = capsys.readouterr().out
    assert '"inserted": 0' in b
    assert '"duplicates": 40' in b


def test_ingest_examples(tmp_path, monkeypatch, capsys):
    from pathlib import Path
    monkeypatch.setenv("NETWORKPULSE_API_KEY", "example-demo-key-strong-123")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "np.db"))
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "np.joblib"))
    main(["bootstrap", "--count", "160"])
    capsys.readouterr()
    fixtures = Path(__file__).resolve().parent.parent / "examples"
    assert main(["ingest-file", "--path", str(fixtures / "zeek-conn.jsonl"), "--format", "zeek"]) == 0
    assert '"inserted": 2' in capsys.readouterr().out
    assert main(["ingest-file", "--path", str(fixtures / "suricata-eve.jsonl"), "--format", "suricata"]) == 0
    assert '"inserted": 2' in capsys.readouterr().out
