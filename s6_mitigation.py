"""STEP 6 - simulated automated mitigation (temporary source blocklist + flow dropping) by REPLAYING test flows.
Writes outputs/mitigation_*.csv and artifacts/incidents.json (one incident per blocked source -> input to the RAG stage).
Usage: python s6_mitigation.py
"""
import json, pickle, itertools
from collections import Counter, defaultdict
import numpy as np, pandas as pd
from config import *
from common import load_meta


def replay(order, src, inst, y, pred, conf, t, params, whitelist, benign=0):
    thr, rep, dur = params["conf_thr"], params["repeat"], params["duration"]
    hits, blocked_until, flagged, nblocks, confsum = Counter(), {}, defaultdict(Counter), Counter(), defaultdict(float)
    first_block, incidents = {}, []
    dropped_atk = dropped_ben = passed_atk = 0
    for i in order:
        key = (inst[i], src[i])
        if key in blocked_until and t[i] < blocked_until[key]:          # fast path: drop flow before it is processed
            if y[i] == benign: dropped_ben += 1
            else: dropped_atk += 1
            continue
        if y[i] != benign: passed_atk += 1
        if pred[i] != benign and conf[i] >= thr:
            hits[key] += 1; flagged[key][pred[i]] += 1; confsum[key] += conf[i]
            if hits[key] >= rep and src[i] not in whitelist:
                nblocks[key] += 1                                   # repeat offenders get exponentially longer blocks
                blocked_until[key] = t[i] + dur * (2 ** min(nblocks[key] - 1, 3))
                if key not in first_block:
                    first_block[key] = t[i]
                    incidents.append({"institution_id": int(key[0]), "src_ip": key[1], "predicted_class": int(flagged[key].most_common(1)[0][0]),
                                      "n_flagged": int(sum(flagged[key].values())), "confidence": round(float(confsum[key] / sum(flagged[key].values())), 3), "triggered_by_true_class": int(y[i]), "time": float(t[i])})
                hits[key] = 0
    atk_total, ben_total = int((y != benign).sum()), int((y == benign).sum())
    atk_srcs = defaultdict(int)
    for i in np.where(y != benign)[0]: atk_srcs[(inst[i], src[i])] += 1
    wrong = sum(1 for k in first_block if atk_srcs.get(k, 0) == 0)
    return {"attack_flows": atk_total, "benign_flows": ben_total,
            "attack_dropped": dropped_atk, "attack_dropped_pct": 100 * dropped_atk / max(atk_total, 1),
            "attack_passed_before_block": passed_atk, "benign_dropped": dropped_ben,
            "benign_dropped_pct": 100 * dropped_ben / max(ben_total, 1),
            "sources_blocked": len(first_block), "wrongly_blocked_sources": wrong}, incidents


def main():
    meta = load_meta(); classes = meta["classes"]
    te = np.load(ART / "test.npz", allow_pickle=False)
    model = pickle.load(open(ART / "global_model.pkl", "rb"))
    proba = model.predict_proba(te["Xb"])
    pred, conf = proba.argmax(1), proba.max(1)
    y, src, inst, ts = te["y"], te["src"], te["inst"], te["ts"]
    if np.isnan(ts).all():
        print("No timestamps: file order is used as time (state this); duration is counted in flows.")
        order = np.arange(len(y)); t = np.arange(len(y), dtype=float); scale_dur = 1.0 / 60
    else:
        order = np.argsort(np.nan_to_num(ts, nan=np.inf), kind="stable"); t = ts - np.nanmin(ts); scale_dur = 1.0
    rows = []
    for thr, rep, dur in itertools.product([0.7, 0.9, 0.95], [1, 3, 5], [600, 3600]):
        p = dict(conf_thr=thr, repeat=rep, duration=dur * scale_dur)
        m, _ = replay(order, src, inst, y, pred, conf, t, p, WHITELIST)
        rows.append({"conf_thr": thr, "repeat": rep, "duration_s": dur, **m})
    df = pd.DataFrame(rows).round(3); df.to_csv(OUT / "mitigation_sweep.csv", index=False)
    print(df[["conf_thr", "repeat", "duration_s", "attack_dropped_pct", "attack_passed_before_block", "benign_dropped_pct", "sources_blocked", "wrongly_blocked_sources"]].to_string(index=False))
    p = dict(MITIGATION, duration=MITIGATION["duration"] * scale_dur)
    m, inc = replay(order, src, inst, y, pred, conf, t, p, WHITELIST)
    pd.Series(m).round(3).to_csv(OUT / "mitigation_default.csv")
    for k in inc:
        k["predicted_class"] = classes[k["predicted_class"]]; k["triggered_by_true_class"] = classes[k["triggered_by_true_class"]]
        k["institution"] = INSTITUTIONS[k.pop("institution_id")]
    json.dump(inc, open(ART / "incidents.json", "w"), indent=1)
    print("\nDEFAULT settings", MITIGATION, "->", m, f"\n{len(inc)} incidents saved for the RAG stage")


if __name__ == "__main__":
    main()
