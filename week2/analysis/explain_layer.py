# analysis/explain_layer.py
import joblib
import json
import numpy as np
import pandas as pd
from pathlib import Path
from analysis.feature_extractor import extract_features

ARTIFACT_DIR = Path("artifacts")
_explainer = None          # lazy-loaded — shap_explainer.pkl is ~50MB
_feature_names = None

def _load():
    global _explainer, _feature_names
    if _explainer is None:
        _explainer = joblib.load(ARTIFACT_DIR / "shap_explainer.pkl")
        with open(ARTIFACT_DIR / "feature_names.json") as f:
            _feature_names = json.load(f)

def get_shap_explanation(query: str, top_n: int = 10) -> dict:
    """
    Compute per-sample SHAP values for a single query.
    Returns the top_n contributing features, matching the
    force plot format from Section 7c of the Week 1 notebook.
    """
    _load()

    feats = extract_features(query)
    feat_df = pd.DataFrame([feats], columns=_feature_names)
    shap_values = _explainer.shap_values(feat_df)[0]   # shape: (25,)

    shap_df = pd.DataFrame({
        "feature":    _feature_names,
        "shap_value": shap_values,
        "feat_value": feat_df.iloc[0].values,
    }).sort_values("shap_value", ascending=False)

    # Split into drivers (toward attack) and suppressors (toward benign)
    drivers    = shap_df[shap_df["shap_value"] > 0].head(top_n)
    suppressors = shap_df[shap_df["shap_value"] < 0].tail(top_n)

    def to_list(df):
        return [
            {
                "feature":    row["feature"],
                "shap_value": round(float(row["shap_value"]), 4),
                "feat_value": round(float(row["feat_value"]), 4),
            }
            for _, row in df.iterrows()
        ]

    return {
        "drivers":     to_list(drivers),
        "suppressors": to_list(suppressors),
        "base_value":  round(float(_explainer.expected_value), 4),
    }