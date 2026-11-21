"""STEP 1 - clean CICIDS2017 CSVs -> artifacts/clean_X.npy + clean_meta.pkl
Usage: python s1_preprocess.py
"""
import json, glob
import numpy as np, pandas as pd
from config import RAW_DIR, ART, OUT, CANON, MAX_BENIGN, SEED

IDENT = {"flow id", "flow_id", "source ip", "src ip", "source port", "src port", "destination ip", "dst ip",
         "destination port", "dst port", "timestamp", "label", "attack", "attack_number", "attempted category"}


def map_label(s):
    t = str(s).lower().replace("\ufffd", "-").replace("\x96", "-")
    if "benign" in t: return "BENIGN"
    if "web attack" in t or "xss" in t or "sql injection" in t: return "WebAttack"
    if "ddos" in t: return "DDoS"
    if "dos" in t or "heartbleed" in t: return "DoS"
    if "portscan" in t or "port scan" in t: return "PortScan"
    if "patator" in t: return "BruteForce"
    if "bot" in t: return "Botnet"
    if "infiltration" in t: return "Infiltration"
    return None


def find(cols, *names):
    low = {c.lower(): c for c in cols}
    for n in names:
        if n in low: return low[n]
    return None


def main():
    files = sorted(glob.glob(str(RAW_DIR / "*.csv")))
    assert files, f"No CSV files in {RAW_DIR}. Put the CICIDS2017 CSVs there (or run make_synthetic.py)."
    rng = np.random.default_rng(SEED)
    per_file_benign = int(1.5 * MAX_BENIGN / len(files)) + 1
    Xs, metas, feat_names, unknown = [], [], None, set()
    for f in files:
        df = pd.read_csv(f, encoding="latin1", low_memory=False, skipinitialspace=True)
        df.columns = df.columns.str.strip()
        lab = find(df.columns, "label", "attack")
        src = find(df.columns, "source ip", "src ip")
        tsc = find(df.columns, "timestamp")
        df = df[df[lab].astype(str).str.lower() != "label"]            # repeated header rows
        y = df[lab].map(map_label)
        unknown |= set(df.loc[y.isna(), lab].unique())
        keep_cols = [c for c in df.columns if c.lower() not in IDENT]
        X = df[keep_cols].apply(pd.to_numeric, errors="coerce").astype("float32")
        X = X.loc[:, ~X.columns.duplicated()]
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        ok = (~X.isna().any(axis=1)) & y.notna()
        X, y = X[ok], y[ok]
        meta = pd.DataFrame({"label": y.values,
                             "src": df.loc[ok, src].astype(str).values if src else None,
                             "ts":pd.to_datetime(df.loc[ok, tsc], errors="coerce", dayfirst=True, format="mixed").values if tsc else pd.NaT})
        dup = pd.util.hash_pandas_object(X.assign(_y=y.values), index=False).duplicated().values
        X, meta = X[~dup], meta[~dup]
        b = np.where(meta.label.values == "BENIGN")[0]
        if len(b) > per_file_benign:
            drop = rng.choice(b, len(b) - per_file_benign, replace=False)
            m = np.ones(len(meta), bool); m[drop] = False
            X, meta = X[m], meta[m]
        feat_names = list(X.columns) if feat_names is None else feat_names
        Xs.append(X[feat_names].values); metas.append(meta)
        print(f"{pathlib_name(f)}: kept {len(meta):>7} rows")
    if unknown: print("WARNING unmapped labels dropped:", unknown)
    X = np.vstack(Xs); meta = pd.concat(metas, ignore_index=True)
    del Xs
    dup = pd.util.hash_pandas_object(pd.DataFrame(X).assign(_y=meta.label.values), index=False).duplicated().values
    X, meta = X[~dup], meta[~dup].reset_index(drop=True)
    b = np.where(meta.label.values == "BENIGN")[0]
    if len(b) > MAX_BENIGN:
        drop = rng.choice(b, len(b) - MAX_BENIGN, replace=False)
        m = np.ones(len(meta), bool); m[drop] = False
        X, meta = X[m], meta[m].reset_index(drop=True)
    const = X.std(0) == 0                                              # constant columns carry no information
    X, feat_names = X[:, ~const], [f for f, c in zip(feat_names, const) if not c]
    classes = [c for c in CANON if c in set(meta.label)]
    meta["y"] = meta.label.map({c: i for i, c in enumerate(classes)}).astype("int16")
    if meta.src.isna().all() or (meta.src == "None").all():            # no Source IP in this CSV version
        print("No Source IP column: assigning SYNTHETIC host ids (state this in the paper).")
        n = len(meta)
        meta["src"] = [f"10.0.{rng.integers(0, 4)}.{rng.integers(1, 250)}" if l == "BENIGN" else f"172.16.{CANON.index(l)}.{rng.integers(1, 4)}"
                       for l in meta.label.values]
        meta["ts"] = pd.NaT
    h = meta.ts.dt.hour
    meta["ts"] = meta.ts.where(h >= 8, meta.ts + pd.Timedelta(hours=12))
    np.save(ART / "clean_X.npy", X.astype("float32"))
    meta.to_pickle(ART / "clean_meta.pkl")
    with open(ART / "clean_info.json", "w") as f:
        json.dump({"features": feat_names, "classes": classes}, f)
    counts = meta.label.value_counts().reindex(classes)
    counts.to_csv(OUT / "class_distribution.csv")
    print("\nRows:", len(meta), " Features:", len(feat_names), "\n", counts.to_string())


def pathlib_name(p):
    return p.replace("\\", "/").split("/")[-1]


if __name__ == "__main__":
    main()
