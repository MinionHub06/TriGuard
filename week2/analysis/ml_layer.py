import shap
import numpy as np
import pandas as pd
from models.model_loader import loader


class MLLayer:
    def __init__(self):
        self.loader   = loader
        self.explainer = None   # lazy-loaded after artifacts are ready

    def _ensure_explainer(self):
        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.loader.model)

    def predict(self, features: dict):
        """
        Run XGBoost + SHAP on a feature dict.

        Returns:
            prob          (float)  — attack probability 0.0-1.0
            top_features  (list)   — top 5 SHAP contributors
        """
        self._ensure_explainer()

        df     = pd.DataFrame([features])[self.loader.feature_names]
        X_sc   = self.loader.scaler.transform(df)

        prob   = float(self.loader.model.predict_proba(X_sc)[0][1])

        shap_vals = self.explainer.shap_values(X_sc)
        # shap_values may return list (old shap) or ndarray (new shap)
        if isinstance(shap_vals, list):
            sv = shap_vals[1][0]
        else:
            sv = shap_vals[0]

        top = sorted(
            zip(self.loader.feature_names, sv),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:5]

        top_features = [
            {"feature": k, "shap": round(float(v), 4)}
            for k, v in top
        ]

        return prob, top_features