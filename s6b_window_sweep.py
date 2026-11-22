import pickle, numpy as np, pandas as pd
from config import ART, OUT, WHITELIST
from s6_mitigation import replay

te = np.load(ART / "test.npz")
model = pickle.load(open(ART / "global_model.pkl", "rb"))
p = model.predict_proba(te["Xb"]); pred, conf = p.argmax(1), p.max(1)
y, src, inst, ts = te["y"], te["src"], te["inst"], te["ts"]
wl = WHITELIST | {"192.168.10.50", "192.168.10.51"}      # gateway/DNS + web and file servers (policy, not tuned on results)

rows = []
for excl in (False, True):
    m = (src != "172.16.0.1") if excl else np.ones(len(y), bool)
    order = np.argsort(np.nan_to_num(ts[m], nan=np.inf), kind="stable"); t = ts[m] - np.nanmin(ts)
    for rep in (3, 5):
        for win in (60, 300, float("inf")):
            r, _ = replay(order, src[m], inst[m], y[m], pred[m], conf[m], t,
                          dict(conf_thr=0.9, repeat=rep, duration=600, window=win), wl)
            rows.append({"excl_172.16.0.1": excl, "repeat": rep, "window_s": win,
                         **{k: round(r[k], 3) for k in ("attack_dropped_pct", "attack_passed_before_block",
                                                         "benign_dropped_pct", "sources_blocked", "wrongly_blocked_sources")}})
df = pd.DataFrame(rows); df.to_csv(OUT / "mitigation_window_sweep.csv", index=False)
print(df.to_string(index=False))