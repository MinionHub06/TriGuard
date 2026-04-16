import joblib
import json
from pathlib import Path


class ModelLoader:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def load(self, artifacts_dir: str = None):
        if self._loaded:
            return self

        if artifacts_dir is None:
            # Walk up from week2/ to find Week1/artifacts
            base = Path(__file__).resolve().parent.parent.parent / "Week1" / "artifacts"
        else:
            base = Path(artifacts_dir)

        if not base.exists():
            raise FileNotFoundError(
                f"Artifacts directory not found: {base}\n"
                f"Make sure Week1/artifacts/ exists relative to the project root.\n"
                f"Expected path: {base.resolve()}"
            )

        print(f"Loading artifacts from: {base.resolve()}")

        self.model   = joblib.load(base / "xgboost_model.pkl")
        print("  [OK] xgboost_model.pkl loaded")

        self.scaler  = joblib.load(base / "scaler.pkl")
        print("  [OK] scaler.pkl loaded")

        with open(base / "feature_names.json") as f:
            self.feature_names = json.load(f)
        print(f"  [OK] feature_names.json loaded ({len(self.feature_names)} features)")

        metadata_path = base / "model_metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                self.metadata = json.load(f)
            print("  [OK] model_metadata.json loaded")
        else:
            self.metadata = {}

        self._loaded = True
        print("All artifacts ready\n")
        return self


# Global singleton — imported by ml_layer.py
loader = ModelLoader()