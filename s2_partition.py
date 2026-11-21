"""STEP 2 - global train/test split, feature selection (XGBoost gain), shared bins,
non-IID partition into N simulated institutions.   Usage: python s2_partition.py
"""
import json
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from config import *
from common import save_json
from fl.gbdt import fit_bins, bin_data, Client
from fl.federated import train
from fl.secagg import PlainAggregator


def gain_importance(Xs, ys, K):
    try:
        import xgboost as xgb
        m = xgb.XGBClassifier(n_estimators=60, max_depth=6, learning_rate=0.3, tree_method="hist",
                              importance_type="gain", n_jobs=-1, random_state=SEED)
        m.fit(Xs, ys)
        print("feature selection: real XGBoost (gain)")
        return m.feature_importances_
    except Exception as e:      # xgboost missing or a class absent -> fall back to our own XGBoost-style trainer
        print(f"feature selection: built-in XGBoost-style trainer ({type(e).__name__})")
        edges = fit_bins(Xs, N_BINS)
        c = Client(0, bin_data(Xs, edges), ys, K, N_BINS)
        ens, _ = train([c], K, dict(GBDT, rounds=15, max_depth=4), PlainAggregator(), verbose=False, name="fs")
        return ens.importance / max(ens.importance.sum(), 1e-12)


def main():
    rng = np.random.default_rng(SEED)
    info = json.load(open(ART / "clean_info.json"))
    classes, feats = info["classes"], info["features"]
    K = len(classes)
    X = np.load(ART / "clean_X.npy", mmap_mode="r")
    meta = pd.read_pickle(ART / "clean_meta.pkl")
    y = meta.y.values.astype(int)
    n = len(y)

    # 1) stratified global train/test split
    test_mask = np.zeros(n, bool)
    for c in range(K):
        idx = np.where(y == c)[0]; rng.shuffle(idx)
        test_mask[idx[:max(1, int(round(TEST_FRAC * len(idx))))]] = True
    tr, te = np.where(~test_mask)[0], np.where(test_mask)[0]

    # 2) small PUBLIC sample (train side only) for feature selection + histogram bin edges
    pub = np.concatenate([rng.choice(tr[y[tr] == c], min((y[tr] == c).sum(), max(int(PUBLIC_FRAC * (y[tr] == c).sum()), 50)), replace=False)
                          for c in range(K)])
    pub.sort()
    Xp = np.asarray(X[pub])
    imp = gain_importance(Xp, y[pub], K)
    sel = np.argsort(-imp)[:N_FEATURES]
    sel = sel[imp[sel] > 0]
    sel_names = [feats[i] for i in sel]
    edges = fit_bins(Xp[:, sel], N_BINS)
    pd.DataFrame({"feature": sel_names, "gain_importance": imp[sel]}).to_csv(OUT / "selected_features.csv", index=False)
    print("Selected features:", sel_names)

    Xsel = np.asarray(X[:, sel])
    Xb = bin_data(Xsel, edges)

    # 3) non-IID partition of the TRAIN set (Dirichlet over each attack class; benign split evenly)
    P = np.zeros((K, N_CLIENTS))
    for c in range(K):
        P[c] = np.ones(N_CLIENTS) / N_CLIENTS if c == 0 else rng.dirichlet([DIRICHLET_ALPHA] * N_CLIENTS)
    owner = np.zeros(n, int)
    for c in range(K):
        idx = tr[y[tr] == c]; rng.shuffle(idx)
        owner[idx] = rng.choice(N_CLIENTS, len(idx), p=P[c])
    counts = np.zeros((N_CLIENTS, K), int)
    for i in range(N_CLIENTS):
        idx = tr[owner[tr] == i]
        np.savez(ART / f"client_{i}.npz", Xb=Xb[idx], y=y[idx])
        counts[i] = np.bincount(y[idx], minlength=K)
    # test flows are assigned to institutions with the same skew (their "live traffic")
    inst = np.zeros(len(te), int)
    for c in range(K):
        m = y[te] == c
        inst[m] = rng.choice(N_CLIENTS, m.sum(), p=P[c])
    ts = meta.ts.values[te]
    ts_sec = np.where(pd.isna(ts), np.nan, pd.to_datetime(ts).astype("int64") / 1e9) if meta.ts.notna().any() else np.full(len(te), np.nan)
    np.savez(ART / "test.npz", Xb=Xb[te], y=y[te], src=np.asarray(meta.src.values[te], dtype="U45"), ts=ts_sec, inst=inst)
    save_json({"classes": classes, "features": sel_names, "edges": [e.tolist() for e in edges], "n_bins": N_BINS,
               "P": P.tolist(), "n_clients": N_CLIENTS, "n_train": int(len(tr)), "n_test": int(len(te))}, ART / "meta.json")

    df = pd.DataFrame(counts, index=INSTITUTIONS, columns=classes)
    df.to_csv(OUT / "partition_counts.csv")
    print("\nTraining flows per institution:\n", df.to_string())
    fig, ax = plt.subplots(figsize=(8, 3.5))
    im = ax.imshow(np.log10(counts + 1), cmap="Blues")
    ax.set_xticks(range(K)); ax.set_xticklabels(classes, rotation=30, ha="right")
    ax.set_yticks(range(N_CLIENTS)); ax.set_yticklabels(INSTITUTIONS)
    for i in range(N_CLIENTS):
        for j in range(K): ax.text(j, i, counts[i, j], ha="center", va="center", fontsize=7)
    ax.set_title("Non-IID partition (training flows per institution)"); plt.colorbar(im, label="log10(count+1)")
    plt.tight_layout(); plt.savefig(OUT / "partition_heatmap.png", dpi=200)


if __name__ == "__main__":
    main()
