import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import numpy as np
from fl.secagg import SecAggSession, quantize, dequantize, SecureAggregator, PlainAggregator
from fl.gbdt import Client, fit_bins, bin_data
from fl.federated import train
from common import metrics


def test_masks_cancel_and_hide():
    for n in (2, 3, 5, 7):                       # odd numbers of clients must work too
        s = SecAggSession(n, 1)
        ups = [np.random.default_rng(i).normal(size=500) for i in range(n)]
        q = [quantize(u, 2 ** 24) for u in ups]
        masked = [s.mask(i, q[i], tag=11) for i in range(n)]
        total = np.zeros_like(masked[0])
        for m in masked:
            total = total + m
        assert np.allclose(dequantize(total, 2 ** 24), np.sum(ups, 0), atol=1e-5)
        assert not np.array_equal(masked[0], q[0])           # a single upload is not the real update
    print("secagg: masks cancel exactly for 2,3,5,7 clients")


def make(n, K, F, seed):
    r = np.random.default_rng(seed)
    y = r.integers(0, K, n)
    X = r.normal(0, 1, (n, F)) + (y[:, None] * (np.arange(F)[None, :] % 3 == 0)) * 1.2
    return X, y


def test_fed_equals_central_and_secure_equals_plain():
    K, F, B = 4, 6, 16
    X, y = make(6000, K, F, 0)
    Xt, yt = make(2000, K, F, 1)
    edges = fit_bins(X, B)
    Xb, Xtb = bin_data(X, edges), bin_data(Xt, edges)
    cfg = dict(rounds=6, max_depth=4, lr=0.3, lam=1.0, gamma=0.0, min_child_weight=1.0)
    parts = np.array_split(np.arange(len(y)), 3)
    cl = lambda: [Client(i, Xb[p], y[p], K, B) for i, p in enumerate(parts)]
    e_plain, _ = train(cl(), K, cfg, PlainAggregator(), verbose=False, name="p")
    sec = SecureAggregator(3, 2 ** 24)
    e_sec, _ = train(cl(), K, cfg, sec, verbose=False, name="s")
    e_cen, _ = train([Client(0, Xb, y, K, B)], K, cfg, PlainAggregator(), verbose=False, name="c")
    acc = lambda e: (e.predict(Xtb) == yt).mean()
    agree = (e_plain.predict(Xtb) == e_sec.predict(Xtb)).mean()
    agree_c = (e_plain.predict(Xtb) == e_cen.predict(Xtb)).mean()
    print(f"acc plain-fed={acc(e_plain):.4f} secure-fed={acc(e_sec):.4f} central={acc(e_cen):.4f}")
    print(f"prediction agreement secure vs plain={agree:.4f}; fed vs central={agree_c:.4f}; verified aggregations={sec.verified_ok}")
    assert acc(e_plain) > 0.6 and agree > 0.99 and agree_c > 0.99


if __name__ == "__main__":
    test_masks_cancel_and_hide()
    test_fed_equals_central_and_secure_equals_plain()
    print("ALL OK")
