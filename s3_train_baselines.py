"""STEP 3 - baselines: (a) each institution alone, (b) centralised on pooled data.
Same algorithm and hyper-parameters as the federated model => a fair comparison.
Usage: python s3_train_baselines.py
"""
import numpy as np, pickle
from config import *
from common import metrics, save_json, load_meta
from fl.gbdt import Client
from fl.federated import train
from fl.secagg import PlainAggregator


def main():
    meta = load_meta(); classes, K, B = meta["classes"], len(meta["classes"]), meta["n_bins"]
    te = np.load(ART / "test.npz")
    ev = (te["Xb"], te["y"])
    data = [np.load(ART / f"client_{i}.npz") for i in range(N_CLIENTS)]
    res = {}
    for i, d in enumerate(data):
        print(f"--- local-only {INSTITUTIONS[i]} ({len(d['y'])} flows)")
        ens, log = train([Client(0, d["Xb"], d["y"], K, B)], K, GBDT, PlainAggregator(), classes, eval_data=ev,
                         verbose=False, name=f"local{i}")
        m = metrics(te["y"], ens.predict(te["Xb"]), classes)
        res[f"local_{INSTITUTIONS[i]}"] = m
        print(f"    acc={m['accuracy']:.4f} macroF1={m['macro_f1']:.4f} FAR={m['far']:.4f} AMR={m['amr']:.4f}")
    print("--- centralised (pooled raw data)")
    Xall = np.vstack([d["Xb"] for d in data]); yall = np.concatenate([d["y"] for d in data])
    ens, log = train([Client(0, Xall, yall, K, B)], K, GBDT, PlainAggregator(), classes, eval_data=ev, name="central")
    res["centralised"] = metrics(te["y"], ens.predict(te["Xb"]), classes)
    res["centralised"]["log"] = log
    pickle.dump(ens, open(ART / "central_model.pkl", "wb"))
    try:                                   # optional sanity check against the real XGBoost library
        import xgboost as xgb
        m = xgb.XGBClassifier(n_estimators=GBDT["rounds"], max_depth=GBDT["max_depth"], learning_rate=GBDT["lr"],
                              tree_method="hist", n_jobs=-1,max_bin=meta["n_bins"], min_child_weight=0.01)
        m.fit(Xall, yall)
        res["xgboost_library_centralised"] = metrics(te["y"], m.predict(te["Xb"]), classes)
        print("xgboost library (centralised): acc=%.4f macroF1=%.4f" % (res["xgboost_library_centralised"]["accuracy"], res["xgboost_library_centralised"]["macro_f1"]))
    except Exception as e:
        print("(xgboost library not used:", type(e).__name__, ")")
    save_json(res, OUT / "results_baselines.json")


if __name__ == "__main__":
    main()
