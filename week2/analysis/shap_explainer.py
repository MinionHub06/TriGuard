# analysis/shap_explainer.py
"""
SHAP explanation helper for the /api/explain endpoint.

Loads artifacts/shapexplainer.pkl (saved in Week 1 Section 8a) once at startup
and exposes explain_prediction() for the Flask route to call.

The explainer is lazy-loaded so the test suite and health-check endpoint can
import this module without triggering the full joblib load.
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

ARTIFACT_DIR   = Path("artifacts")
EXPLAINER_PATH = ARTIFACT_DIR / "shapexplainer.pkl"
FEATURE_PATH   = ARTIFACT_DIR / "featurenames.json"

# ── Lazy singletons ────────────────────────────────────────────────────────────
_explainer    = None
_feature_names: list[str] = []


def _load_artifacts() -> bool:
    global _explainer, _feature_names
    if _explainer is not None:
        return True
    try:
        import joblib, json
        _explainer     = joblib.load(EXPLAINER_PATH)
        _feature_names = json.loads(FEATURE_PATH.read_text())
        log.info("SHAPExplainer: loaded %s features from %s", len(_feature_names), EXPLAINER_PATH)
        return True
    except FileNotFoundError as exc:
        log.error("SHAPExplainer: artifact missing — %s", exc)
        return False
    except Exception as exc:
        log.error("SHAPExplainer: load failed — %s", exc)
        return False


# ── Public API ─────────────────────────────────────────────────────────────────

def explain_prediction(feature_dict: dict, top_n: int = 10) -> Optional[dict]:
    """
    Compute SHAP values for a single prediction.

    Parameters
    ----------
    feature_dict : dict
        The 25-feature dict returned by extract_features() — exact same format
        used during training (order guaranteed by featurenames.json).
    top_n : int
        Number of top features to return (ranked by |SHAP value|).

    Returns
    -------
    dict with keys:
        top_features     list[dict]  — [{feature, shap_value, feature_value,
                                          direction}, ...] sorted descending
                                        by |shap_value|
        base_value       float       — SHAP expected_value (model baseline)
        prediction_delta float       — sum of all SHAP values
                                        (= model output − base_value)
        risk_direction   str         — "attack" | "benign"
    Returns None if the explainer artifact is unavailable.
    """
    if not _load_artifacts():
        return None

    import pandas as pd

    # Build a single-row DataFrame in the exact feature order the model was
    # trained on (featurenames.json guarantees the column order).
    row = {feat: feature_dict.get(feat, 0) for feat in _feature_names}
    X   = pd.DataFrame([row], columns=_feature_names)

    try:
        shap_vals = _explainer.shap_values(X)   # shape (1, 25) for TreeExplainer
        sv        = np.array(shap_vals[0])       # 1-D array, length = n_features
    except Exception as exc:
        log.error("SHAPExplainer: shap_values() failed — %s", exc)
        return None

    base_value       = float(_explainer.expected_value)
    prediction_delta = float(sv.sum())

    # Rank features by descending |SHAP value|
    ranked_idx = np.argsort(np.abs(sv))[::-1][:top_n]
    top_features = [
        {
            "feature":       _feature_names[i],
            "shap_value":    round(float(sv[i]), 5),
            "feature_value": round(float(X.iloc[0, i]), 4),
            "direction":     "attack" if sv[i] > 0 else "benign",
        }
        for i in ranked_idx
    ]

    return {
        "top_features":      top_features,
        "base_value":        round(base_value, 5),
        "prediction_delta":  round(prediction_delta, 5),
        "risk_direction":    "attack" if prediction_delta > 0 else "benign",
    }


def explain_batch(feature_dicts: list[dict], top_n: int = 8) -> list[Optional[dict]]:
    """
    Compute SHAP explanations for a list of feature dicts in one
    TreeExplainer call — significantly faster than calling
    explain_prediction() in a loop for large batches.

    Parameters
    ----------
    feature_dicts : list[dict]
        List of 25-feature dicts, one per payload (same format as
        explain_prediction).
    top_n : int
        Top features to return per prediction.

    Returns
    -------
    List of explanation dicts (same schema as explain_prediction),
    in the same order as feature_dicts. Returns a list of None values
    if artifacts are unavailable.
    """
    if not _load_artifacts():
        return [None] * len(feature_dicts)

    import pandas as pd

    rows = [
        {feat: fd.get(feat, 0) for feat in _feature_names}
        for fd in feature_dicts
    ]
    X = pd.DataFrame(rows, columns=_feature_names)

    try:
        shap_vals = _explainer.shap_values(X)   # shape (n_samples, n_features)
        sv_matrix = np.array(shap_vals)
    except Exception as exc:
        log.error("SHAPExplainer: batch shap_values() failed — %s", exc)
        return [None] * len(feature_dicts)

    base_value = float(_explainer.expected_value)
    results    = []

    for i, sv in enumerate(sv_matrix):
        delta      = float(sv.sum())
        ranked_idx = np.argsort(np.abs(sv))[::-1][:top_n]
        top_features = [
            {
                "feature":       _feature_names[j],
                "shap_value":    round(float(sv[j]), 5),
                "feature_value": round(float(X.iloc[i, j]), 4),
                "direction":     "attack" if sv[j] > 0 else "benign",
            }
            for j in ranked_idx
        ]
        results.append({
            "top_features":      top_features,
            "base_value":        round(base_value, 5),
            "prediction_delta":  round(delta, 5),
            "risk_direction":    "attack" if delta > 0 else "benign",
        })

    return results


def reload_artifacts() -> bool:
    """
    Force-reload artifacts from disk — useful after retraining
    the model without restarting Flask.

        curl -X POST /api/admin/reload-explainer

    Returns True if reload succeeded.
    """
    global _explainer, _feature_names
    _explainer     = None
    _feature_names = []
    return _load_artifacts()


def explainer_status() -> dict:
    """
    Return the current load state of the explainer — consumed
    by GET /health to populate the 'shap_explainer' field.
    """
    loaded = _explainer is not None
    return {
        "loaded":         loaded,
        "n_features":     len(_feature_names) if loaded else 0,
        "artifact_path":  str(EXPLAINER_PATH),
        "artifact_exists": EXPLAINER_PATH.exists(),
    }