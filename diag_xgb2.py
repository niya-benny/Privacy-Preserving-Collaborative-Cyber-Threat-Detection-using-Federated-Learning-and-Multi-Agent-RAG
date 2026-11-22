import numpy as np, xgboost as xgb
from config import ART, N_CLIENTS, GBDT
from common import load_meta, metrics
meta = load_meta(); classes = meta["classes"]
d = [np.load(ART / f"client_{i}.npz") for i in range(N_CLIENTS)]
X = np.vstack([c["Xb"] for c in d]); y = np.concatenate([c["y"] for c in d])
te = np.load(ART / "test.npz")
print("xgboost version:", xgb.__version__)
for mcw in (1, 0.1, 0.01):
    m = xgb.XGBClassifier(n_estimators=GBDT["rounds"], max_depth=GBDT["max_depth"], learning_rate=GBDT["lr"],
                          tree_method="hist", n_jobs=-1, max_bin=meta["n_bins"], min_child_weight=mcw)
    m.fit(X, y)
    r = metrics(te["y"], m.predict(te["Xb"]), classes)
    print(f"min_child_weight={mcw:<5} acc={r['accuracy']:.4f} macroF1={r['macro_f1']:.4f} "
          f"WebAttack R={r['per_class']['WebAttack']['recall']:.3f} Infiltration R={r['per_class']['Infiltration']['recall']:.3f}")