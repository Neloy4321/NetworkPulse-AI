import csv
from pathlib import Path

import pytest

from networkpulse.evaluation.unsw import evaluate_unsw, load_partition, row_features


COLS = ["id", "dur", "sbytes", "dbytes", "spkts", "dpkts", "rate", "sload", "dload", "proto", "state", "service", "attack_cat", "label"]


def create_csv(path: Path, n: int, seed: int):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for i in range(n):
            attack = i % 5 == 0
            w.writerow({"id": i + seed*10000, "dur": .01+i*.013 if not attack else .0005,
                        "sbytes": 140+i*3+seed*0.31 if not attack else 23000+i+seed*0.31, "dbytes": 50+i*4 if not attack else 0,
                        "spkts": 3+(i%7), "dpkts": 3+(i%11) if not attack else 0,
                        "rate": 20+i/10, "sload": 100+i, "dload": 200+i,
                        "proto": "tcp" if i%7 else "udp", "state": "FIN" if not attack else "INT",
                        "service": "http", "attack_cat": "Normal" if not attack else "Exploits", "label": int(attack)})


def test_benchmark_models_independent_holdout(tmp_path):
    a, b = tmp_path/"train.csv", tmp_path/"test.csv"
    create_csv(a, 500, 1)
    create_csv(b, 240, 2)
    r = evaluate_unsw(a, b, max_train=0, max_test=0)
    assert r["sample_counts"]["test"] == 240
    assert set(r["evaluation"]) == {"isolation_forest", "lof_novelty", "rule_based"}
    assert r["temporal_split_verified"] is False
    assert "sha256" in r["dataset_provenance"]["train"]
    for item in r["evaluation"].values():
        assert set(item["confusion_matrix"]) == {"tn", "fp", "fn", "tp"}
        assert 0 <= item["false_positive_rate"] <= 1


def test_no_cross_partition_duplicates(tmp_path):
    a, b = tmp_path/"train.csv", tmp_path/"test.csv"
    create_csv(a, 400, 1)
    b.write_bytes(a.read_bytes())
    with pytest.raises(ValueError, match="no independent"):
        evaluate_unsw(a, b, max_train=0, max_test=0)


def test_reject_corruption(tmp_path):
    p=tmp_path/"bad.csv"
    p.write_text("dur,sbytes,label\n5,2,0\n")
    with pytest.raises(ValueError, match="missing UNSW"):
        load_partition(p)
    record={name:"4" for name in ("dur","sbytes","dbytes","spkts","dpkts","rate","sload","dload")}
    record.update({"proto":"tcp","state":"FIN"})
    record["dur"]="inf"
    with pytest.raises(ValueError, match="invalid numeric"):
        row_features(record)
