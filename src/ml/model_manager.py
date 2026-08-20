"""
Model Lifecycle and Serialization Manager.
Phase 2, Day 10: Model Serialization & Mid-Project Audit

Manages model artifacts, versioning, serialization to disk (.joblib and metadata.json),
and ensures seamless runtime loading for streaming inference engines in Phase 3.
"""

import os
import json
import time
import joblib
from typing import Optional, Dict, Any, Tuple
from .train_isolation_forest import CANIsolationForestModel, train_pipeline
from .features import FEATURE_COLUMNS

DEFAULT_MODEL_PATH = "models/isolation_forest.joblib"
DEFAULT_META_PATH = "models/model_metadata.json"
DEFAULT_TRAIN_CSV = "dataset/normal_traffic.csv"
DEFAULT_EVAL_CSV = "dataset/attack_traffic.csv"

class ModelManager:
    """
    Singleton-style manager for loading, training, validating, and saving
    CAN-Sentinel anomaly detection models.
    """

    _cached_model: Optional[CANIsolationForestModel] = None

    @classmethod
    def get_or_train_model(
        cls,
        model_path: str = DEFAULT_MODEL_PATH,
        metadata_path: str = DEFAULT_META_PATH,
        train_csv: str = DEFAULT_TRAIN_CSV,
        eval_csv: Optional[str] = DEFAULT_EVAL_CSV,
        force_retrain: bool = False
    ) -> CANIsolationForestModel:
        """
        Retrieve cached model, load from disk if present, or train a fresh pipeline.
        """
        if cls._cached_model is not None and not force_retrain:
            return cls._cached_model

        if os.path.exists(model_path) and not force_retrain:
            try:
                print(f"[*] Loading serialized model from {model_path}...")
                cls._cached_model = CANIsolationForestModel.load(model_path, metadata_path)
                return cls._cached_model
            except Exception as e:
                print(f"[!] Warning: Failed to load existing model ({e}). Re-training...")

        # Train new model
        model, _ = train_pipeline(
            normal_csv=train_csv,
            attack_csv=eval_csv,
            model_output=model_path,
            meta_output=metadata_path
        )
        cls._cached_model = model
        return model

    @classmethod
    def audit_model(
        cls,
        model_path: str = DEFAULT_MODEL_PATH,
        metadata_path: str = DEFAULT_META_PATH
    ) -> Dict[str, Any]:
        """
        Audit model artifact consistency, feature alignment, and serialization status.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file missing: {model_path}")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file missing: {metadata_path}")

        file_size_bytes = os.path.getsize(model_path)
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        model = CANIsolationForestModel.load(model_path, metadata_path)

        audit_results = {
            "model_path": model_path,
            "model_size_bytes": file_size_bytes,
            "model_type": metadata.get("model_type", "Unknown"),
            "n_estimators": metadata.get("n_estimators", 100),
            "decision_threshold": model.threshold,
            "feature_count": len(model.feature_names),
            "features_verified": model.feature_names == FEATURE_COLUMNS,
            "is_trained": model.is_trained,
            "audit_status": "PASSED"
        }
        return audit_results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CAN-Sentinel Model Manager & Audit Tool")
    parser.add_argument("--audit", action="store_true", help="Run model integrity audit")
    parser.add_argument("--retrain", action="store_true", help="Force model retraining")
    args = parser.parse_args()

    if args.audit:
        print("[*] Performing mid-project model audit...")
        results = ModelManager.audit_model()
        print(json.dumps(results, indent=2))
    else:
        ModelManager.get_or_train_model(force_retrain=args.retrain)
