"""Central configuration. Edit values here, not inside the scripts."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "data" / "raw"      # put the CICIDS2017 CSV files here
ART = ROOT / "artifacts"             # intermediate data + trained models
OUT = ROOT / "outputs"               # tables, plots, reports for the paper
KB_DIR = ROOT / "kb"                 # knowledge-base documents
for _p in (RAW_DIR, ART, OUT, KB_DIR):
    _p.mkdir(parents=True, exist_ok=True)

SEED = 42

# ---- data ----
CANON = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack", "Infiltration"]
MAX_BENIGN = 300_000        # benign flows are down-sampled to keep an 8 GB laptop happy (state this in the paper)
N_FEATURES = 20             # top-N features by XGBoost gain
N_BINS = 32                 # histogram bins per feature
TEST_FRAC = 0.20
PUBLIC_FRAC = 0.10          # public sample used ONLY for feature selection + bin edges

# ---- federation ----
N_CLIENTS = 5
INSTITUTIONS = [f"Institution_{chr(65 + i)}" for i in range(N_CLIENTS)]
DIRICHLET_ALPHA = 0.5       # smaller = more non-IID
GBDT = dict(rounds=30, max_depth=5, lr=0.3, lam=1.0, gamma=0.0, min_child_weight=1.0)
SECAGG_SCALE = 2 ** 24      # fixed-point scale used before masking

# ---- simulated mitigation ----
MITIGATION = dict(conf_thr=0.90, repeat=3, duration=600)     # duration in seconds
WHITELIST = {"192.168.10.1", "192.168.10.3"}   # gateway / DNS-DC in CICIDS2017 -- VERIFY against the dataset documentation

# ---- RAG / LLM ----
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3:8b")     # on weak hardware try: llama3.2:3b
NUM_CTX = 4096
MAX_CHUNK_CHARS = 700
MAX_FIELD_CHARS = 80
TOP_K = 4
