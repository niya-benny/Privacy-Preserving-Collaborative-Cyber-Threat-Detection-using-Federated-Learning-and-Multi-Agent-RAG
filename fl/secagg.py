"""
Secure Aggregation by pairwise additive masking (Bonawitz-style core idea).

For every pair (i, j) with i < j the two clients share a seed. Client i ADDS the
mask derived from it, client j SUBTRACTS the same mask. Individually every upload
looks like uniform random noise; in the sum all masks cancel exactly.
Arithmetic is done on fixed-point integers modulo 2^64 so cancellation is exact.

SIMULATION LIMITS (state them in the paper): the pairwise seeds are derived from a
master secret instead of a real Diffie-Hellman key agreement; there is no dropout
recovery; the server is assumed honest-but-curious (not malicious).
"""
import hashlib
import numpy as np


def quantize(x, scale):
    return np.round(x * scale).astype(np.int64).view(np.uint64)


def dequantize(u, scale):
    return u.view(np.int64).astype(np.float64) / scale


class SecAggSession:
    def __init__(self, n_clients, master_secret=0):
        self.n = n_clients
        self.seed = {}
        for i in range(n_clients):
            for j in range(i + 1, n_clients):
                d = hashlib.sha256(f"{master_secret}|{i}|{j}".encode()).digest()
                self.seed[(i, j)] = int.from_bytes(d[:8], "little")

    def mask(self, cid, q, tag):
        out = q.copy()
        for other in range(self.n):
            if other == cid:
                continue
            a, b = (cid, other) if cid < other else (other, cid)
            rng = np.random.default_rng([self.seed[(a, b)], tag])
            r = rng.integers(0, 2 ** 64, size=q.shape, dtype=np.uint64, endpoint=False)
            out = out + r if cid < other else out - r      # uint64 wraps modulo 2^64
        return out


class PlainAggregator:
    secure = False

    def __init__(self):
        self.bytes_up = 0
        self.calls = 0

    def __call__(self, payloads, tag):
        self.calls += 1
        self.bytes_up += sum(p.nbytes for p in payloads)
        return np.sum(payloads, axis=0)


class SecureAggregator:
    secure = True

    def __init__(self, n_clients, scale, master_secret=0, verify=True):
        self.sess, self.scale, self.verify = SecAggSession(n_clients, master_secret), scale, verify
        self.bytes_up = 0
        self.calls = 0
        self.verified_ok = 0
        self.leak_corr = []      # |corr(masked upload, true upload)| -> should be ~0

    def __call__(self, payloads, tag):
        self.calls += 1
        qs = [quantize(p, self.scale) for p in payloads]
        masked = [self.sess.mask(i, q, tag) for i, q in enumerate(qs)]
        self.bytes_up += sum(m.nbytes for m in masked)
        total = np.zeros_like(masked[0])
        for m in masked:
            total = total + m
        if self.verify:
            plain = np.zeros_like(qs[0])
            for q in qs:
                plain = plain + q
            assert np.array_equal(total, plain), "Secure aggregate != plain aggregate!"
            self.verified_ok += 1
            if len(self.leak_corr) < 50 and qs[0].size > 10:
                a = payloads[0].ravel()
                b = masked[0].view(np.int64).astype(np.float64).ravel()
                if a.std() > 0 and b.std() > 0:
                    self.leak_corr.append(abs(float(np.corrcoef(a, b)[0, 1])))
        return dequantize(total, self.scale)
