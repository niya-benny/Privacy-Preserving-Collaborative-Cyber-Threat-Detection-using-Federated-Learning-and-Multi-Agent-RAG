import json
import numpy as np
from config import ART, OUT


def confusion(y, p, K):
    cm = np.zeros((K, K), dtype=np.int64)
    np.add.at(cm, (y, p), 1)
    return cm


def metrics(y, p, classes, benign=0):
    K = len(classes)
    cm = confusion(y, p, K)
    tp = np.diag(cm).astype(float)
    fp = cm.sum(0) - tp
    fn = cm.sum(1) - tp
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / np.maximum(tp + fn, 1)
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    sup = cm.sum(1)
    present = sup > 0
    atk = y != benign
    pa = p != benign
    fp_b = int(((~atk) & pa).sum())
    tn_b = int(((~atk) & (~pa)).sum())
    amr = float((atk & ~pa).sum() / max(atk.sum(), 1))
    return {
        "accuracy": float(tp.sum() / cm.sum()),
        "macro_precision": float(prec[present].mean()),
        "macro_recall": float(rec[present].mean()),
        "macro_f1": float(f1[present].mean()),
        "weighted_f1": float((f1 * sup).sum() / sup.sum()),
        "far": fp_b / max(fp_b + tn_b, 1),     # false alarm rate (benign flagged as attack)
        "amr": amr,                            # attack miss ratio (attack called benign)
        "detection_rate": 1 - amr,
        "per_class": {classes[i]: {"precision": float(prec[i]), "recall": float(rec[i]),
                                   "f1": float(f1[i]), "support": int(sup[i])} for i in range(K)},
        "confusion": cm.tolist(),
    }


def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def load_meta():
    with open(ART / "meta.json") as f:
        return json.load(f)
