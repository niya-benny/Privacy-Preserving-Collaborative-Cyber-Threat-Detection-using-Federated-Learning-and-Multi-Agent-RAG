import pickle, numpy as np, pandas as pd
from config import ART
te = np.load(ART / "test.npz")
model = pickle.load(open(ART / "global_model.pkl", "rb"))
p = model.predict_proba(te["Xb"]); pred, conf = p.argmax(1), p.max(1)
df = pd.DataFrame({"src": te["src"], "benign": te["y"] == 0, "attack": te["y"] != 0,
                   "fp": (te["y"] == 0) & (pred != 0) & (conf >= 0.9)})
g = df.groupby("src").agg(benign=("benign", "sum"), attack=("attack", "sum"), fp=("fp", "sum"))
print("Sources with >=3 confident benign false positives, by benign volume:")
print(g[g.fp >= 3].sort_values("benign", ascending=False).head(12).to_string())
print("\nBenign flows from sources that also send attack flows (top 8):")
print(g[(g.attack > 0) & (g.benign > 0)].sort_values("benign", ascending=False).head(8).to_string())