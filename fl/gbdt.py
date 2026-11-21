"""
Histogram-based gradient boosted trees with the XGBoost objective
(second-order gradients, L2 leaf regularisation `lam`, split penalty `gamma`).

The training loop is *federated*: a Client only ever returns gradient/Hessian
HISTOGRAMS (per node, feature, bin). The server picks the best split from the
summed histograms and broadcasts the tree structure. Raw rows never leave a client.
"""
import numpy as np


# ---------------------------------------------------------------- binning
def fit_bins(X, n_bins):
    qs = np.linspace(0, 1, n_bins + 1)[1:-1]
    return [np.unique(np.quantile(X[:, f], qs)) for f in range(X.shape[1])]


def bin_data(X, edges):
    Xb = np.empty(X.shape, dtype=np.uint8)
    for f, e in enumerate(edges):
        Xb[:, f] = np.searchsorted(e, X[:, f], side="right")
    return Xb


def softmax(z):
    z = z - z.max(1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(1, keepdims=True)


# ---------------------------------------------------------------- model
class Tree:
    def __init__(self, max_nodes):
        self.feat = -np.ones(max_nodes, np.int16)
        self.thr = np.zeros(max_nodes, np.int16)
        self.left = -np.ones(max_nodes, np.int32)
        self.right = -np.ones(max_nodes, np.int32)
        self.val = np.zeros(max_nodes, np.float32)

    def trim(self, n):
        for a in ("feat", "thr", "left", "right", "val"):
            setattr(self, a, getattr(self, a)[:n].copy())

    def predict(self, Xb):
        n = Xb.shape[0]
        node = np.zeros(n, np.int32)
        ar = np.arange(n)
        while True:
            f = self.feat[node]
            internal = f >= 0
            if not internal.any():
                break
            go_left = Xb[ar, np.maximum(f, 0)] <= self.thr[node]
            nxt = np.where(go_left, self.left[node], self.right[node])
            node = np.where(internal, nxt, node)
        return self.val[node]


class Ensemble:
    def __init__(self, K, n_features, classes=None, features=None, edges=None):
        self.K, self.classes, self.features, self.edges = K, classes, features, edges
        self.rounds = []                        # rounds[r][k] -> Tree
        self.importance = np.zeros(n_features)  # total gain per feature

    def raw(self, Xb, upto=None):
        out = np.zeros((Xb.shape[0], self.K))
        for trees in self.rounds[:upto]:
            for k, t in enumerate(trees):
                out[:, k] += t.predict(Xb)
        return out

    def predict_proba(self, Xb):
        return softmax(self.raw(Xb))

    def predict(self, Xb):
        return self.raw(Xb).argmax(1)

    # deployment helper: raw (already feature-selected) float matrix -> probabilities
    def predict_proba_raw(self, X):
        return self.predict_proba(bin_data(np.asarray(X, dtype=np.float64), self.edges))


def find_splits(H, lam, gamma, mcw):
    """H: (m, F, B, 2) summed histograms. Returns best split per node."""
    G, Hs = H[..., 0], H[..., 1]
    Gt, Ht = G[:, 0, :].sum(1), Hs[:, 0, :].sum(1)
    GL = np.cumsum(G, axis=2)[:, :, :-1]
    HL = np.cumsum(Hs, axis=2)[:, :, :-1]
    GR, HR = Gt[:, None, None] - GL, Ht[:, None, None] - HL
    gain = 0.5 * (GL ** 2 / (HL + lam) + GR ** 2 / (HR + lam)
                  - (Gt ** 2 / (Ht + lam))[:, None, None]) - gamma
    gain = np.where((HL >= mcw) & (HR >= mcw), gain, -np.inf)
    m = gain.shape[0]
    flat = gain.reshape(m, -1)
    arg = flat.argmax(1)
    ar = np.arange(m)
    best = flat[ar, arg]
    f, b = np.divmod(arg, gain.shape[2])
    return Gt, Ht, best, f, b, GL[ar, f, b], HL[ar, f, b]


# ---------------------------------------------------------------- client
class Client:
    """One institution. Holds binned features + labels privately."""

    def __init__(self, cid, Xb, y, K, n_bins):
        self.cid, self.Xb, self.y, self.K, self.B = cid, Xb, y.astype(np.int64), K, n_bins
        self.n, self.F = Xb.shape
        self.score = np.zeros((self.n, K))

    def begin_round(self):
        p = softmax(self.score)
        g = p.copy()
        g[np.arange(self.n), self.y] -= 1.0
        self.g, self.h = g, np.maximum(2.0 * p * (1.0 - p), 1e-6)

    def begin_tree(self):
        self.node = np.zeros(self.n, np.int32)

    def histograms(self, k, active, max_nodes):
        loc = np.full(max_nodes, -1, np.int32)
        loc[active] = np.arange(len(active))
        li = loc[self.node]
        r = np.nonzero(li >= 0)[0]
        m, B = len(active), self.B
        out = np.zeros((m, self.F, B, 2))
        if len(r) == 0:
            return out
        base = li[r].astype(np.int64) * B
        Xr, g, h = self.Xb[r], self.g[r, k], self.h[r, k]
        for f in range(self.F):
            idx = base + Xr[:, f]
            out[:, f, :, 0] = np.bincount(idx, g, m * B).reshape(m, B)
            out[:, f, :, 1] = np.bincount(idx, h, m * B).reshape(m, B)
        return out

    def advance(self, tree):
        f = tree.feat[self.node]
        go_left = self.Xb[np.arange(self.n), np.maximum(f, 0)] <= tree.thr[self.node]
        nxt = np.where(go_left, tree.left[self.node], tree.right[self.node])
        self.node = np.where(f >= 0, nxt, self.node).astype(np.int32)

    def end_tree(self, k, tree):
        self.score[:, k] += tree.val[self.node]
