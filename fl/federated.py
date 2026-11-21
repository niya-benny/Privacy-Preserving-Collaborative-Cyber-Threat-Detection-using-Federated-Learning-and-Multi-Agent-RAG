import time
import zlib
import numpy as np
from .gbdt import Tree, Ensemble, find_splits
from common import metrics


def grow_tree(clients, k, cfg, aggregator, tag, ens):
    D = cfg["max_depth"]
    max_nodes = 2 ** (D + 1) - 1
    t = Tree(max_nodes)
    for c in clients:
        c.begin_tree()
    active, n_nodes = [0], 1
    for depth in range(D):
        if not active:
            break
        payloads = [c.histograms(k, active, max_nodes) for c in clients]
        H = aggregator(payloads, tag).reshape(len(active), clients[0].F, clients[0].B, 2)
        tag += 1
        Gt, Ht, gain, f, b, GL, HL = find_splits(H, cfg["lam"], cfg["gamma"], cfg["min_child_weight"])
        new_active = []
        for i, nid in enumerate(active):
            t.val[nid] = -Gt[i] / (Ht[i] + cfg["lam"]) * cfg["lr"]
            if gain[i] > 0:
                l, r = n_nodes, n_nodes + 1
                n_nodes += 2
                t.feat[nid], t.thr[nid], t.left[nid], t.right[nid] = f[i], b[i], l, r
                t.val[l] = -GL[i] / (HL[i] + cfg["lam"]) * cfg["lr"]
                t.val[r] = -(Gt[i] - GL[i]) / (Ht[i] - HL[i] + cfg["lam"]) * cfg["lr"]
                ens.importance[f[i]] += gain[i]
                new_active += [l, r]
        for c in clients:
            c.advance(t)
        active = new_active
    t.trim(n_nodes)
    return t, tag


def train(clients, K, cfg, aggregator, classes=None, features=None, edges=None,
          eval_data=None, verbose=True, name="fed"):
    """One boosting round = K trees (one per class). Every tree level needs one
    histogram exchange. `eval_data=(Xb_test, y_test)` logs test accuracy/F1 per round."""
    F = clients[0].F
    ens = Ensemble(K, F, classes, features, edges)
    log, test_score = [], None
    if eval_data is not None:
        Xte, yte = eval_data
        test_score = np.zeros((len(yte), K))
    tag = (zlib.crc32(name.encode()) % 10_000) * 1_000_000
    t0 = time.time()
    for r in range(cfg["rounds"]):
        for c in clients:
            c.begin_round()
        round_trees = []
        for k in range(K):
            tree, tag = grow_tree(clients, k, cfg, aggregator, tag, ens)
            for c in clients:
                c.end_tree(k, tree)
            round_trees.append(tree)
            if test_score is not None:
                test_score[:, k] += tree.predict(Xte)
        ens.rounds.append(round_trees)
        entry = {"round": r + 1, "seconds": round(time.time() - t0, 1), "bytes_up": int(aggregator.bytes_up)}
        if test_score is not None:
            m = metrics(yte, test_score.argmax(1), classes or list(range(K)))
            entry.update(accuracy=m["accuracy"], macro_f1=m["macro_f1"], far=m["far"], amr=m["amr"])
        log.append(entry)
        if verbose:
            extra = f" acc={entry['accuracy']:.4f} macroF1={entry['macro_f1']:.4f}" if "accuracy" in entry else ""
            print(f"[{name}] round {r + 1}/{cfg['rounds']}  {entry['seconds']}s{extra}", flush=True)
    return ens, log
