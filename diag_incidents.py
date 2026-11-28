import pickle, numpy as np
from collections import Counter, deque
from config import ART, MITIGATION
from common import load_meta

classes = load_meta()["classes"]
te = np.load(ART / "test.npz")
model = pickle.load(open(ART / "global_model.pkl", "rb"))
p = model.predict_proba(te["Xb"]); pred, conf = p.argmax(1), p.max(1)
y, src, inst, ts = te["y"], te["src"], te["inst"], te["ts"]
t = ts - np.nanmin(ts)
sel = np.where((src == "172.16.0.1") & (inst == 0))[0]
sel = sel[np.argsort(t[sel], kind="stable")]
print(f"Institution_A, source 172.16.0.1: {len(sel)} flows\n\nHour-by-hour predicted classes (hours since the first flow):")
for h in sorted(set((t[sel] // 3600).astype(int))):
    m = sel[(t[sel] // 3600).astype(int) == h]
    print(f"  hour {h:3d}: " + ", ".join(f"{classes[c]}={n}" for c, n in Counter(pred[m]).most_common()))

thr, rep, dur, win = MITIGATION["conf_thr"], MITIGATION["repeat"], MITIGATION["duration"], MITIGATION.get("window", float("inf"))
hits, until, nb = deque(), -1.0, 0
print("\nEvery block event for this source:")
for i in sel:
    if t[i] < until:
        continue
    if pred[i] != 0 and conf[i] >= thr:
        hits.append((t[i], pred[i]))
        while t[i] - hits[0][0] > win:
            hits.popleft()
        if len(hits) >= rep:
            nb += 1
            length = dur * 2 ** min(nb - 1, 3)
            until = t[i] + length
            print(f"  hour {t[i] / 3600:6.2f}: block #{nb} for {length:.0f}s, class = {classes[Counter(c for _, c in hits).most_common(1)[0][0]]}")
            hits.clear()
