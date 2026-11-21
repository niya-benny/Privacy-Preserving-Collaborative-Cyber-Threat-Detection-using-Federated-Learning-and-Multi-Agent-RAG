"""STEP 4 - federated training with Secure Aggregation.
Usage: python s4_train_federated.py [--no-secagg] [--poison 0.3] [--compare-plain]
  --poison p   : institution 0 flips a fraction p of its labels (data-poisoning experiment)
"""
import argparse, pickle
import numpy as np
from config import *
from common import metrics, save_json, load_meta
from fl.gbdt import Client
from fl.federated import train
from fl.secagg import SecureAggregator, PlainAggregator


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-secagg", action="store_true")
    ap.add_argument("--poison", type=float, default=0.0)
    ap.add_argument("--compare-plain", action="store_true")
    a = ap.parse_args()
    meta = load_meta(); classes, K, B = meta["classes"], len(meta["classes"]), meta["n_bins"]
    te = np.load(ART / "test.npz"); ev = (te["Xb"], te["y"])
    rng = np.random.default_rng(SEED)

    def clients():
        out = []
        for i in range(N_CLIENTS):
            d = np.load(ART / f"client_{i}.npz"); y = d["y"].copy()
            if a.poison > 0 and i == 0:
                flip = rng.random(len(y)) < a.poison
                y[flip] = rng.integers(0, K, flip.sum())
                print(f"Institution_A poisoned: {flip.sum()} labels flipped")
            out.append(Client(i, d["Xb"], y, K, B))
        return out

    agg = PlainAggregator() if a.no_secagg else SecureAggregator(N_CLIENTS, SECAGG_SCALE, master_secret=SEED)
    ens, log = train(clients(), K, GBDT, agg, classes, meta["features"], [np.array(e) for e in meta["edges"]],
                     eval_data=ev, name="federated" + ("_poisoned" if a.poison else ""))
    m = metrics(te["y"], ens.predict(te["Xb"]), classes)
    res = {"metrics": m, "log": log, "secure": agg.secure, "poison": a.poison,
           "comm_MB_uploaded": agg.bytes_up / 1e6, "aggregations": agg.calls}
    if agg.secure:
        res["secagg_verified_aggregations"] = agg.verified_ok
        res["secagg_mean_abs_corr_masked_vs_true"] = float(np.mean(agg.leak_corr)) if agg.leak_corr else None
        print(f"SecAgg: {agg.verified_ok}/{agg.calls} aggregates equal the plain sum exactly; "
              f"mean |corr(masked upload, true upload)| = {res['secagg_mean_abs_corr_masked_vs_true']:.4f}")
    if a.compare_plain and agg.secure:
        e2, _ = train(clients(), K, GBDT, PlainAggregator(), classes, verbose=False, name="plain_cmp")
        res["prediction_agreement_secure_vs_plain"] = float((e2.predict(te["Xb"]) == ens.predict(te["Xb"])).mean())
        print("prediction agreement secure vs plain:", res["prediction_agreement_secure_vs_plain"])
    print(f"FEDERATED: acc={m['accuracy']:.4f} macroF1={m['macro_f1']:.4f} FAR={m['far']:.4f} AMR={m['amr']:.4f}  upload={res['comm_MB_uploaded']:.0f} MB")
    suffix = "_poisoned" if a.poison else ""
    save_json(res, OUT / f"results_federated{suffix}.json")
    if not a.poison:
        pickle.dump(ens, open(ART / "global_model.pkl", "wb"))     # <- the model "redeployed" to every institution


if __name__ == "__main__":
    main()
