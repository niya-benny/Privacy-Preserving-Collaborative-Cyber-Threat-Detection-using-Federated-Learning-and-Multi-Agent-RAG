import pickle, numpy as np, pandas as pd
from config import ART, WHITELIST
from s6_mitigation import replay

te = np.load(ART / "test.npz")
model = pickle.load(open(ART / "global_model.pkl", "rb"))
p = model.predict_proba(te["Xb"]); pred, conf = p.argmax(1), p.max(1)
y, src, inst, ts = te["y"], te["src"], te["inst"], te["ts"]
order = np.argsort(np.nan_to_num(ts, nan=np.inf), kind="stable"); t = ts - np.nanmin(ts)
rows = []
for dur in (10, 30, 60, 120, 300, 600, 3600):
    r, _ = replay(order, src, inst, y, pred, conf, t, dict(conf_thr=0.9, repeat=3, duration=dur, window=60), WHITELIST)
    rows.append({"duration_s": dur, **{k: round(r[k], 3) for k in ("attack_dropped_pct", "attack_passed_before_block", "benign_dropped_pct", "sources_blocked")}})
print(pd.DataFrame(rows).to_string(index=False))

pd.DataFrame(rows).to_csv("outputs/mitigation_duration_sweep.csv", index=False)