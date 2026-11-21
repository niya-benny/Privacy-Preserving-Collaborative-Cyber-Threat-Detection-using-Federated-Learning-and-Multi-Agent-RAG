"""STEP 5 - tables + figures for the paper (outputs/).   Usage: python s5_evaluate.py"""
import json
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from config import *

base = json.load(open(OUT / "results_baselines.json"))
fed = json.load(open(OUT / "results_federated.json"))
classes = list(fed["metrics"]["per_class"])
cols = ["accuracy", "macro_precision", "macro_recall", "macro_f1", "far", "amr"]

rows = {k.replace("local_", "Local only - "): v for k, v in base.items() if k.startswith("local_")}
if "centralised" in base: rows["Centralised (pooled data)"] = base["centralised"]
if "xgboost_library_centralised" in base: rows["XGBoost library (centralised)"] = base["xgboost_library_centralised"]
rows["Federated + SecAgg (ours)" if fed["secure"] else "Federated (no SecAgg)"] = fed["metrics"]
tab = pd.DataFrame({k: {c: v[c] for c in cols} for k, v in rows.items()}).T
tab.columns = ["Accuracy", "Precision (macro)", "Recall (macro)", "F1 (macro)", "FAR", "AMR"]
tab.round(4).to_csv(OUT / "table_model_comparison.csv")
open(OUT / "table_model_comparison.md", "w").write(tab.round(4).to_markdown() if hasattr(tab, "to_markdown") else tab.round(4).to_string())
print(tab.round(4).to_string())

# per-class recall: local vs federated vs central
pc = pd.DataFrame({k: {c: v["per_class"][c]["recall"] for c in classes} for k, v in rows.items()})
pc.round(4).to_csv(OUT / "table_per_class_recall.csv")
fig, ax = plt.subplots(figsize=(9, 4))
w = 0.8 / 3
loc_mean = pc[[c for c in pc.columns if c.startswith("Local")]].mean(axis=1)
for j, (lab, ser) in enumerate([("Local only (mean of 5)", loc_mean), ("Centralised", pc.get("Centralised (pooled data)")), ("Federated + SecAgg", pc.iloc[:, -1])]):
    if ser is not None: ax.bar(np.arange(len(classes)) + j * w, ser.values, w, label=lab)
ax.set_xticks(np.arange(len(classes)) + w); ax.set_xticklabels(classes, rotation=25, ha="right")
ax.set_ylabel("Recall"); ax.set_title("Per-class recall on the global test set"); ax.legend(); plt.tight_layout()
plt.savefig(OUT / "fig_per_class_recall.png", dpi=200); plt.close()

# convergence
lg = pd.DataFrame(fed["log"])
fig, ax = plt.subplots(1, 2, figsize=(9, 3.4))
ax[0].plot(lg["round"], lg["accuracy"], label="Accuracy"); ax[0].plot(lg["round"], lg["macro_f1"], label="Macro-F1")
if "centralised" in base and "log" in base["centralised"]:
    cl = pd.DataFrame(base["centralised"]["log"]); ax[0].plot(cl["round"], cl["macro_f1"], "--", label="Centralised macro-F1")
ax[0].set_xlabel("Boosting round"); ax[0].legend(); ax[0].set_title("Convergence")
ax[1].plot(lg["round"], lg["bytes_up"] / 1e6); ax[1].set_xlabel("Boosting round"); ax[1].set_ylabel("Cumulative upload (MB)"); ax[1].set_title("Communication cost")
plt.tight_layout(); plt.savefig(OUT / "fig_convergence.png", dpi=200); plt.close()

# confusion matrix
cm = np.array(fed["metrics"]["confusion"]); cmn = cm / np.maximum(cm.sum(1, keepdims=True), 1)
fig, ax = plt.subplots(figsize=(6.5, 5.5)); im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes, rotation=35, ha="right"); ax.set_yticks(range(len(classes))); ax.set_yticklabels(classes)
for i in range(len(classes)):
    for j in range(len(classes)): ax.text(j, i, f"{cmn[i, j]:.2f}", ha="center", va="center", fontsize=7, color="white" if cmn[i, j] > .5 else "black")
ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title("Federated model - normalised confusion matrix"); plt.tight_layout()
plt.savefig(OUT / "fig_confusion_matrix.png", dpi=200); plt.close()

# secure aggregation + poisoning summary
lines = [f"Secure Aggregation: {fed.get('secagg_verified_aggregations')}/{fed['aggregations']} aggregates identical to plain sum",
         f"mean |corr(masked, true)| = {fed.get('secagg_mean_abs_corr_masked_vs_true')}",
         f"prediction agreement secure vs plain = {fed.get('prediction_agreement_secure_vs_plain')}",
         f"upload volume = {fed['comm_MB_uploaded']:.0f} MB over {len(lg)} rounds"]
try:
    p = json.load(open(OUT / "results_federated_poisoned.json"))
    lines.append(f"Poisoning (one institution, {p['poison']:.0%} labels flipped): macroF1 {fed['metrics']['macro_f1']:.4f} -> {p['metrics']['macro_f1']:.4f}; accuracy {fed['metrics']['accuracy']:.4f} -> {p['metrics']['accuracy']:.4f}")
except FileNotFoundError:
    pass
open(OUT / "secagg_summary.txt", "w").write("\n".join(lines)); print("\n".join(lines))
