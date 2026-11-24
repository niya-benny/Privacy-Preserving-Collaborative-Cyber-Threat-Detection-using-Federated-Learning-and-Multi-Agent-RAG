"""Helpers for the 'Test the model' tab of the demo app."""
import numpy as np
import pandas as pd


def representative_values(xb_row, edges):
    """One raw value per feature that falls into the given histogram bin, so that bin_data(values) == xb_row.
    (The test set only stores binned data, so these are approximate values at each bin's lower boundary.)"""
    vals = []
    for b, e in zip(xb_row, edges):
        e = np.asarray(e, dtype=float)
        vals.append(float(e[int(b) - 1]) if b > 0 else float(e[0]) - 1.0)
    return np.array(vals)


def predict_frame(model, df):
    """Predict for a DataFrame that has the model's feature columns (names are stripped of stray spaces).
    Returns (frame with predictions, probability matrix, number of rows skipped for NaN/inf values)."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    missing = [f for f in model.features if f not in df.columns]
    if missing:
        raise ValueError("Missing columns: " + ", ".join(missing))
    X = df[model.features].apply(pd.to_numeric, errors="coerce").astype("float64")
    ok = np.isfinite(X.values).all(axis=1)
    if not ok.any():
        raise ValueError("No usable rows (all rows contain NaN/inf in the feature columns).")
    proba = model.predict_proba_raw(X.values[ok])
    out = df.loc[ok].copy()
    out["predicted_class"] = [model.classes[i] for i in proba.argmax(1)]
    out["confidence"] = proba.max(1).round(4)
    return out, proba, int((~ok).sum())
