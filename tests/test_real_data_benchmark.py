"""Synthetic fixture contract tests. These are not real IDS performance results."""
import csv
import io
import zipfile

import pytest

from tools.real_data_benchmark import SPECS, _float, evaluate, parse_flow, unique


def test_no_ip_uid_label_or_time_in_features():
    r = {"ts": "1556016001", "src_ip": "10.0.0.2", "dst_ip": "10.2.1.3",
         "dst_port": "443", "proto": "tcp", "duration": "2",
         "src_bytes": "110", "dst_bytes": "210", "src_pkts": "4",
         "dst_pkts": "6", "conn_state": "SF", "label": "1",
         "type": "scanning", "uid": "abc"}
    first = parse_flow(r, "toniot")
    altered = {**r, "ts": "1556016002", "src_ip": "192.0.2.30",
               "dst_ip": "198.51.100.20", "label": "0", "type": "normal",
               "uid": "other"}
    assert first["fingerprint"] == parse_flow(altered, "toniot")["fingerprint"]
    assert unique([first, parse_flow(altered, "toniot")])[1] == 1
    assert "src_ip" not in first["features"]


def test_unsw_raw_and_cic_units_validation():
    r = {"Stime": "1421927414", "dur": "2", "sbytes": "10", "dbytes": "20",
         "Spkts": "3", "Dpkts": "4", "dsport": "53", "proto": "udp",
         "state": "CON", "Label": "0", "attack_cat": ""}
    assert parse_flow(r, "unsw_raw")["label"] == 0
    c = {" Flow Duration": "1000000", " Total Fwd Packets": "2",
         "Total Backward Packets": "3", "Total Length of Fwd Packets": "100",
         "Total Length of Bwd Packets": "150",
         " Destination Port": "80", " Label": "BENIGN"}
    assert parse_flow(c, "cic2017")["features"]["log_duration_s"] == pytest.approx(0.69314718056)
    with pytest.raises(ValueError, match="empty CIC label"):
        parse_flow({**c, " Label": ""}, "cic2017")
    with pytest.raises(ValueError, match="invalid"):
        _float("Infinity", "counter")


def fixture(path, *, overlap=False):
    names = ("ts", "src_ip", "dst_ip", "dst_port", "proto", "duration",
             "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
             "conn_state", "label", "type")
    with zipfile.ZipFile(path, "w") as archive:
        for name, n, base in (
            (SPECS["toniot"][0], 900, 1556000000),
            (SPECS["toniot"][1], 600, 1556000000 if overlap else 1557000000),
        ):
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=names)
            writer.writeheader()
            for i in range(n):
                abnormal = i % 4 == 0
                writer.writerow({
                    "ts": str(base + i * 10), "src_ip": "10.0.0.1",
                    "dst_ip": "10.2.0.1",
                    "dst_port": str(40 + i % 3000 + (1000 if name == SPECS["toniot"][1] else 0)),
                    "proto": "tcp" if i % 3 else "udp",
                    "duration": str(.1 + i * .0001),
                    "src_bytes": str(20000 + i if abnormal else 130 + i),
                    "dst_bytes": str(i % 5 if abnormal else 400 + i),
                    "src_pkts": str(2 + i % 9), "dst_pkts": str(3 + i % 4),
                    "conn_state": "SF", "label": str(int(abnormal)),
                    "type": "scan" if abnormal else "normal",
                })
            archive.writestr(name, buffer.getvalue())


def test_external_holdout_protocol_and_time_overlap_rejection(tmp_path):
    path = tmp_path / "fixture.zip"
    fixture(path)
    result = evaluate(path, "toniot", max_train=700, max_test=420)
    assert result["split"]["training_and_test_capture_time_separated"] is True
    assert result["split"]["calibration_chronological"] is True
    assert result["sample_counts"]["test_attacks"] > 0
    assert set(result["model_results"]) == {
        "isolation_forest", "lof_novelty", "supervised_random_forest", "fixed_rules"
    }
    assert result["held_out_dataset_is_production_traffic"] is False
    assert result["split"]["site_independence_verified"] is False
    assert result["source_files"]["train"]["valid_rows_full_scan"] == 900
    fixture(path, overlap=True)
    with pytest.raises(ValueError, match="capture periods overlap"):
        evaluate(path, "toniot", max_train=700, max_test=420)
