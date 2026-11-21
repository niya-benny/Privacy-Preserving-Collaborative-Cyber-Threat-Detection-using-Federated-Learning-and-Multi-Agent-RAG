"""Creates a small CICIDS2017-LIKE dataset in data/raw/ so you can dry-run the whole
pipeline in minutes BEFORE downloading the real data. Not a substitute for real data."""
import numpy as np, pandas as pd
from config import RAW_DIR, SEED

rng = np.random.default_rng(SEED)
FEATS = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Fwd Packet Length Max",
         "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow IAT Std", "Fwd IAT Mean", "Fwd IAT Std",
         "Idle Mean", "Active Mean", "FIN Flag Count", "SYN Flag Count", "Packet Length Variance",
         "Avg Bwd Segment Size", "Subflow Fwd Bytes", "Subflow Bwd Bytes", "Flow Bytes/s", "Flow Packets/s",
         "Init_Win_bytes_forward", "Destination Port Group", "Noise A", "Noise B", "Noise C"]
SPEC = {  # label: (rows, centre-shift seed)
    "BENIGN": 20000, "DoS Hulk": 5000, "DDoS": 5000, "PortScan": 4000, "FTP-Patator": 1500,
    "SSH-Patator": 1500, "Bot": 600, "Web Attack \x96 Brute Force": 500, "Web Attack \x96 XSS": 200, "Infiltration": 40}
ATTACKERS = {l: [f"172.16.0.{i}" for i in range(1, 4)] for l in SPEC if l != "BENIGN"}
rows = []
for li, (label, n) in enumerate(SPEC.items()):
    centre = rng.normal(0, 1.5, len(FEATS)) * (0 if label == "BENIGN" else 1)
    X = np.abs(rng.normal(centre, 1.0 + 0.2 * (li % 3), (n, len(FEATS))) * 100)
    X[:, -3:] = rng.normal(0, 1, (n, 3))      # pure noise columns
    df = pd.DataFrame(X, columns=FEATS)
    pool = [f"192.168.10.{i}" for i in range(1, 80)] if label == "BENIGN" else ATTACKERS[label]
    df.insert(0, "Flow ID", [f"f{li}-{i}" for i in range(n)])
    df.insert(1, "Source IP", rng.choice(pool, n))
    df.insert(2, "Source Port", rng.integers(1024, 65535, n))
    df.insert(3, "Destination IP", "192.168.10.50")
    df.insert(4, "Destination Port", rng.integers(1, 1024, n))
    df.insert(5, "Protocol", rng.choice([6, 17], n))
    t0 = pd.Timestamp("2017-07-05 09:00") + pd.to_timedelta(rng.integers(0, 6 * 3600, n), unit="s")
    df.insert(6, "Timestamp", t0.strftime("%d/%m/%Y %H:%M:%S"))
    df["Label"] = label
    rows.append(df)
full = pd.concat(rows).sample(frac=1, random_state=SEED).reset_index(drop=True)
full.loc[::997, "Flow Bytes/s"] = np.inf          # dirty values, like the real files
full.loc[::1499, "Flow Packets/s"] = np.nan
full = pd.concat([full, full.iloc[:300]])         # duplicates
full.columns = [" " + c if c not in ("Flow ID",) else c for c in full.columns]   # real files have leading spaces
for i, idx in enumerate(np.array_split(np.arange(len(full)), 3)):
    full.iloc[idx].to_csv(RAW_DIR / f"synthetic_part{i + 1}.csv", index=False)
print("wrote", len(full), "rows to", RAW_DIR)
