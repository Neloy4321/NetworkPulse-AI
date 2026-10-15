"""Native UNSW -> TON-IoT domain shift experiment; NOT production certification."""
from __future__ import annotations
import argparse, csv, hashlib, io, json, math, random, tempfile, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from sklearn.metrics import average_precision_score, roc_auc_score
from networkpulse.detector import Detector, train
from networkpulse.evaluation.live_unsw import read_reservoir
from networkpulse.generalization_evidence import normalized_flow_fingerprint, wilson_interval
from networkpulse.schemas import FlowEvent

UNSW_SHA = "3c7500f120405b21b44a2bf05134f49491f88a655ae3091fc1b269c4c9ece79a"
TON_SHA = "411ec9768cc06586265095292f3fdc78f10306d26c9e4e227079f7c286520ad0"
REQUIRED = frozenset("ts src_ip src_port dst_ip dst_port proto duration src_bytes dst_bytes src_pkts dst_pkts conn_state label type".split())

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def num(row, key, integer=False):
    try:
        value = float(row[key])
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("Invalid real numeric field: " + key) from error
    if not math.isfinite(value) or value < 0 or (integer and not value.is_integer()):
        raise ValueError("Invalid real numeric value for " + key)
    return int(value) if integer else value

def to_native(row):
    """Do NOT fill in missing fields with fabricated IPs/times/counters."""
    r = {str(k).strip().lower():v for k,v in row.items()}
    if not REQUIRED.issubset(r):
        raise ValueError("Native TON fields missing: " + ",".join(sorted(REQUIRED-set(r))))
    label = str(r["label"]).strip()
    if label not in ("0", "1"):
        raise ValueError("Invalid ground truth")
    protocol = str(r["proto"]).strip().lower()
    return FlowEvent(
        timestamp=datetime.fromtimestamp(num(r,"ts"),tz=timezone.utc),source="canonical",
        src_ip=r["src_ip"], dst_ip=r["dst_ip"],
        src_port=num(r,"src_port",True),dst_port=num(r,"dst_port",True),
        proto=protocol if protocol in ("tcp","udp","icmp") else "other",
        duration=num(r,"duration"),orig_bytes=num(r,"src_bytes",True),
        resp_bytes=num(r,"dst_bytes",True),orig_pkts=num(r,"src_pkts",True),
        resp_pkts=num(r,"dst_pkts",True),
        conn_state=str(r["conn_state"]).strip().lower(),
        label="benign" if label=="0" else "anomaly")

def ton_sample(archive, cap=5000, seed=43):
    if not 1000 <= cap <= 50000:
        raise ValueError("Sample cap must be 1000..50000")
    sample, counts, rejected, valid = [], Counter(), 0, 0
    randomizer = random.Random(seed)
    with archive.open("Network_dataset_23.csv") as stream:
        reader = csv.DictReader(io.TextIOWrapper(stream,encoding="utf-8-sig",newline=""))
        if not REQUIRED.issubset({str(k).strip().lower() for k in reader.fieldnames or ()}):
            raise ValueError("TON dataset lacks authentic native flow fields")
        for row in reader:
            try:
                event = to_native(row)
            except (ValueError,TypeError,OverflowError,KeyError):
                rejected += 1
                continue
            valid += 1
            counts[event.label] += 1
            if len(sample) < cap: sample.append(event)
            else:
                position = randomizer.randrange(valid)
                if position < cap: sample[position] = event
    if valid < cap or rejected > max(10,(valid+rejected)//5):
        raise ValueError("Insufficient valid source rows for credible evaluation")
    return sample, {"full_scan_valid":valid,"full_scan_invalid":rejected,
                    "full_scan_labels":dict(counts),"uniform_sample_seed":seed,
                    "before_dedup":len(sample)}

def unique(items, training_ids=frozenset(), training_flow_hashes=frozenset()):
    seen_ids, seen_flows = set(training_ids), set(training_flow_hashes)
    kept, excluded = [], 0
    for event in items:
        key, flow = event.key(), normalized_flow_fingerprint(event)
        if key in seen_ids or flow in seen_flows:
            excluded += 1
            continue
        seen_ids.add(key);seen_flows.add(flow);kept.append(event)
    return kept, excluded

def metrics(events, detections):
    if not events or len(events)!=len(detections):
        raise ValueError("Native model returned incomplete predictions")
    cm = Counter(dict(tp=0,tn=0,fp=0,fn=0))
    daily = defaultdict(lambda:Counter(dict(tp=0,tn=0,fp=0,fn=0)))
    labels, scores = [], []
    for event, decision in zip(events,detections):
        if type(decision.anomalous) is not bool or not math.isfinite(float(decision.anomaly_score)):
            raise ValueError("Invalid model score")
        actual = event.label=="anomaly"
        cell = ("tp" if decision.anomalous else "fn") if actual else ("fp" if decision.anomalous else "tn")
        cm[cell]+=1;daily[event.timestamp.date().isoformat()][cell]+=1
        labels.append(int(actual));scores.append(float(decision.anomaly_score))
    benign, attack = cm["tn"]+cm["fp"],cm["tp"]+cm["fn"]
    if benign<100 or attack<100:
        raise ValueError("External result lacks >=100 records per class")
    p=cm["tp"]/max(1,cm["tp"]+cm["fp"]);r=cm["tp"]/attack;f=cm["fp"]/benign
    fci=wilson_interval(cm["fp"],benign);rci=wilson_interval(cm["tp"],attack)
    return {
        "confusion_matrix":dict(cm),"benign":benign,"attack":attack,
        "precision":round(p,6),"recall":round(r,6),
        "f1":round(2*p*r/max(1e-12,p+r),6),
        "fpr":round(f,6),
        "false_alarms_per_10000_benign":round(10000*f,2),
        "fpr_wilson95":list(map(lambda x:round(x,6),fci)),
        "recall_wilson95":list(map(lambda x:round(x,6),rci)),
        "pr_auc_ap":round(float(average_precision_score(labels,scores)),6),
        "roc_auc":round(float(roc_auc_score(labels,scores)),6),
        "per_day":[{
            "day":day,"confusion_matrix":dict(v),
            "benign":v["tn"]+v["fp"],"attack":v["tp"]+v["fn"],
            "fpr":round(v["fp"]/(v["tn"]+v["fp"]),6) if v["tn"]+v["fp"] else None,
            "recall":round(v["tp"]/(v["tp"]+v["fn"]),6) if v["tp"]+v["fn"] else None,
        } for day,v in sorted(daily.items())],
        "operational_gate":{"predeclared_max_fpr_upper95":0.05,
                            "predeclared_min_recall_lower95":0.8,
                            "status":"passed" if fci[1]<=0.05 and rci[0]>=0.8 else "failed",
                            "warning":"Wilson intervals optimistic if flows correlate"},
    }

def run(unsw_path,ton_path):
    if digest(unsw_path)!=UNSW_SHA or digest(ton_path)!=TON_SHA:
        raise ValueError("Real source bytes changed from approved checksums")
    with zipfile.ZipFile(unsw_path) as zf:
        train_sample,train_info=read_reservoir(zf,"UNSW-NB15_1.csv",2200,42)
    training,removed_train=unique(train_sample)
    if len(training)<1000: raise ValueError("Insufficient UNSW fit population")
    with zipfile.ZipFile(ton_path) as zf:
        external_sample,external_info=ton_sample(zf)
    test,removed_test=unique(external_sample,
        {e.key() for e in training},
        {normalized_flow_fingerprint(e) for e in training})
    if not test or max(e.timestamp for e in training)>=min(e.timestamp for e in test):
        raise ValueError("External dataset is empty or overlaps source capture time")
    model=train(training,quantile=.995,seed=42,source="UNSW_real_research_cross_dataset")
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/"research-only.joblib"
        model.save(path);model_sha=digest(path)
        frozen=Detector.load(path)  # Only locally created trusted file, not uploads.
        result=metrics(test,frozen.score(test))
        if digest(path)!=model_sha: raise ValueError("Frozen model mutated during evaluation")
    return {
        "schema_version":1,"status":"research_cross_dataset_measurement_completed",
        "original_signed_production_model_tested":False,"production_certified":False,
        "train_dataset":"UNSW-NB15 raw 2015","test_dataset":"TON-IoT 2019",
        "training_zip_sha256":UNSW_SHA,"test_zip_sha256":TON_SHA,
        "train_member":"UNSW-NB15_1.csv","test_member":"Network_dataset_23.csv",
        "native_detector_actual_score_code":True,
        "frozen_research_model_sha256":model_sha,
        "feature_version":frozen.metadata["feature_version"],
        "predeclared_quantile":.995,
        "test_labels_used_for_fit_or_calibration":False,
        "independent_physical_site_audited":False,
        "train_sample":train_info,"test_sample":external_info,
        "train_unique":len(training),"test_unique":len(test),
        "train_duplicates_excluded":removed_train,
        "test_duplicates_excluded":removed_test,
        "evaluation":result,
        "limitations":[
            "Frozen newly trained UNSW research model, not the signed active deployed model.",
            "Published independent dataset families are NOT audited independent physical sites.",
            "UNSW and TON sensor flow semantics may differ; target labels are not independently re-adjudicated.",
            "Uniform reservoir plus dedup may change prevalence; flow-level confidence intervals ignore clustering.",
            "One TON file does not prove replicated capture-day reliability; no real-site alert-hour measurement.",
            "Metric gate failure is retained, not used for external label-guided model optimization.",
        ]}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unsw-zip",type=Path,required=True)
    parser.add_argument("--ton-zip",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(argv)
    if args.output.exists(): parser.error("Refuse to overwrite existing real evidence")
    report=run(args.unsw_zip,args.ton_zip)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as f:
        json.dump(report,f,indent=2,sort_keys=True,allow_nan=False);f.write("\n")
    print(json.dumps({"status":report["status"],"model":report["frozen_research_model_sha256"],
        "test_unique":report["test_unique"],"metrics":report["evaluation"]},sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
