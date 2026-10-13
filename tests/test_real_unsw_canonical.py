"""Schema tests use hand-made rows; NEVER real accuracy claims."""
from datetime import timezone
import pytest
from networkpulse.evaluation.live_unsw import raw_unsw_to_event, evaluate_scores
from networkpulse.detector import Detection

BASE = {
    "srcip": "59.166.0.1", "sport": "4956",
    "dstip": "149.171.126.1", "dsport": "80",
    "proto": "tcp", "state": "FIN", "dur": "2",
    "sbytes": "1024", "dbytes": "2048", "Spkts": "4", "Dpkts": "5",
    "Stime": "1421927414", "Label": "0",
}


def test_original_unsw_raw_to_canonical_event():
    e = raw_unsw_to_event(BASE)
    assert e.label == "benign"
    assert str(e.src_ip) == "59.166.0.1"
    assert e.duration == 2.0
    assert e.timestamp.tzinfo == timezone.utc
    assert e.orig_bytes == 1024 and e.resp_pkts == 5


def test_malformed_raw_fields_never_silently_coerce():
    with pytest.raises(ValueError):
        raw_unsw_to_event({**BASE, "sport": "-"})
    with pytest.raises(ValueError):
        raw_unsw_to_event({**BASE, "Label": "2"})
    with pytest.raises(ValueError):
        raw_unsw_to_event({**BASE, "Spkts": "Infinity"})


def test_native_detector_metrics_preserve_fpr():
    good = raw_unsw_to_event(BASE)
    bad = raw_unsw_to_event({**BASE, "Label": "1", "Stime": "1421927415"})
    d = Detection(anomaly_score=.9, threshold=.5, anomalous=True, risk=90, reasons=[])
    no = Detection(anomaly_score=.1, threshold=.5, anomalous=False, risk=10, reasons=[])
    result = evaluate_scores([good, bad], [no, d])
    assert result["f1"] == 1.0
    assert result["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}
