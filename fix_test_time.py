"""One-off repair: s2_partition.py stored test timestamps with the wrong time unit on newer pandas versions
(everything was compressed by 1000x, so '600 s' blocks lasted ~7 days). This rescales artifacts/test.npz to real seconds
WITHOUT retraining anything. Safe to run twice (it detects that the times are already correct).   Usage: python fix_test_time.py"""
import numpy as np, pandas as pd, shutil
from config import ART

meta = pd.read_pickle(ART / "clean_meta.pkl")
true_span = (meta.ts.max() - meta.ts.min()).total_seconds()
d = np.load(ART / "test.npz", allow_pickle=False)
data = {k: d[k] for k in d.files}
cur = float(np.nanmax(data["ts"]) - np.nanmin(data["ts"]))
ratio = true_span / cur
factor = 10 ** round(np.log10(ratio))
print(f"real time span of the capture: {true_span / 3600:.1f} h | span stored in test.npz: {cur / 3600:.4f} h | ratio {ratio:.1f} -> factor {factor:g}")
if factor == 1:
    print("Times are already in real seconds. Nothing to do.")
else:
    shutil.copy(ART / "test.npz", ART / "test_before_time_fix.npz")
    data["ts"] = data["ts"] * factor
    np.savez(ART / "test.npz", **data)
    print(f"Rescaled. New span: {(np.nanmax(data['ts']) - np.nanmin(data['ts'])) / 3600:.1f} h (backup: test_before_time_fix.npz)")
