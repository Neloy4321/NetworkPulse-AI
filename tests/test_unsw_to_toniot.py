"""Source-schema and safety contract tests, not real external ML evidence."""
from types import SimpleNamespace
import pytest
from networkpulse.evaluation.unsw_to_toniot import REQUIRED,to_native,unique,metrics,num
def row(**change):
    r=dict(ts="1556485778",src_ip="198.51.100.3",dst_ip="203.0.113.4",
           src_port="45000",dst_port="443",proto="tcp",duration="1.2",
           src_bytes="40",dst_bytes="80",src_pkts="2",dst_pkts="5",
           conn_state="SF",label="0",type="normal")
    r.update(change)
    return r
def test_map():
    e=to_native(row())
    assert len(REQUIRED)==14 and e.label=="benign" and e.proto=="tcp"
    assert (e.orig_bytes,e.resp_bytes,e.orig_pkts,e.resp_pkts)==(40,80,2,5)
    assert str(e.src_ip)=="198.51.100.3" and e.timestamp.year==2019
def test_missing_source_not_filled():
    r=row()
    del r["src_ip"]
    with pytest.raises(ValueError,match="Native TON fields"):
        to_native(r)
@pytest.mark.parametrize("bad",[{"src_ip":"bad"},{"src_port":"-1"},{"src_port":"1.2"},
    {"dst_port":"65536"},{"label":"unlabeled"},{"ts":"nan"},{"duration":"inf"},
    {"src_bytes":"-10"},{"conn_state":"X"*40}])
def test_corrupt(bad):
    with pytest.raises((ValueError,TypeError)):
        to_native(row(**bad))
def test_unknown_proto_is_native_other():
    assert to_native(row(proto="gre")).proto=="other"
def test_excludes_train_overlap_and_duplicates():
    a=to_native(row())
    b=to_native(row(src_ip="198.51.100.5",label="1"))
    kept,n=unique([a,a,b],{b.key()})
    assert len(kept)==1 and n==2
def test_failing_fpr_not_hidden():
    ev,pred=[],[]
    for i in range(120):
        ev.append(to_native(row(ts=str(1556485778+i),src_port=str(10000+i))))
        pred.append(SimpleNamespace(anomalous=i<24,anomaly_score=float(i)))
    for i in range(120):
        ev.append(to_native(row(ts=str(1556485778+i),src_port=str(20000+i),label="1")))
        pred.append(SimpleNamespace(anomalous=i<105,anomaly_score=float(i+200)))
    out=metrics(ev,pred)
    assert out["fpr"]==0.2 and out["false_alarms_per_10000_benign"]==2000.
    assert out["confusion_matrix"]["fp"]==24 and out["confusion_matrix"]["fn"]==15
    assert out["operational_gate"]["status"]=="failed"
def test_single_class_not_misreported():
    ev=[to_native(row(ts=str(1556485778+i),src_port=str(10000+i))) for i in range(120)]
    with pytest.raises(ValueError,match="100 records per class"):
        metrics(ev,[SimpleNamespace(anomalous=False,anomaly_score=0.)]*120)
    with pytest.raises(ValueError):
        num({"x":"nan"},"x")
