"""
Isolation Forest Anomaly Detection Model Architecture & Training Pipeline.
Phase 2, Day 8: Isolation Forest Model Architecture

Trains an unsupervised Scikit-Learn Isolation Forest pipeline on baseline
vehicle CAN bus traffic to detect zero-day cyber intrusions (DoS, Spoofing, Fuzzing)
with sub-millisecond per-frame inference latency.
"""

import os
import json
import time
import joblib
import numpy as np
from typing import Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .features import FEATURE_COLUMNS, extract_features_from_csv

class CANIsolationForestModel:
    """
    Unsupervised Isolation Forest Intrusion Detection Engine for CAN bus.
    """

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.03,
        max_samples: Any = "auto",
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_samples = max_samples
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_trained = False
        self.threshold = 0.0
        self.feature_names = FEATURE_COLUMNS

    def fit(self, X: np.ndarray) -> "CANIsolationForestModel":
        """
        Fit the standard scaler and Isolation Forest model on baseline normal traffic.
        """
        if len(X) == 0:
            raise ValueError("Training dataset X cannot be empty.")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model.fit(X_scaled)
        self.is_trained = True

        # Calculate decision threshold from baseline
        scores = self.model.decision_function(X_scaled)
        self.threshold = float(np.percentile(scores, self.contamination * 100))

        return self

    def predict_single(self, feature_vector: np.ndarray) -> Tuple[int, float]:
        """
        Perform ultra-fast single-frame anomaly prediction.
        Returns:
            label: 1 (NORMAL) or -1 (ANOMALY)
            score: raw continuous decision score (negative indicates anomaly)
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before inference.")

        X_reshaped = feature_vector.reshape(1, -1)
        X_scaled = self.scaler.transform(X_reshaped)
        score = float(self.model.decision_function(X_scaled)[0])
        pred = 1 if score >= self.threshold else -1
        return pred, score

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Batch prediction on feature matrix X.
        Returns (predictions, decision_scores).
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before inference.")

        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        preds = np.where(scores >= self.threshold, 1, -1)
        return preds, scores

    def evaluate(self, X: np.ndarray, y_labels: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate anomaly detection performance on labeled ground-truth dataset.
        """
        preds, scores = self.predict(X)
        # Ground truth: 1 for NORMAL, -1 for any ATTACK_*
        y_true = np.where(y_labels == "NORMAL", 1, -1)

        tp = np.sum((y_true == -1) & (preds == -1))
        fp = np.sum((y_true == 1) & (preds == -1))
        tn = np.sum((y_true == 1) & (preds == 1))
        fn = np.sum((y_true == -1) & (preds == 1))

        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = float((tp + tn) / len(y_true)) if len(y_true) > 0 else 0.0

        metrics = {
            "total_samples": int(len(y_true)),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "threshold": round(self.threshold, 6)
        }
        return metrics

    def save(
        self,
        model_path: str = "models/isolation_forest.joblib",
        metadata_path: str = "models/model_metadata.json"
    ) -> None:
        """
        Serialize model pipeline and export JSON metadata.
        """
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(metadata_path)), exist_ok=True)

        payload = {
            "scaler": self.scaler,
            "model": self.model,
            "threshold": self.threshold,
            "feature_names": self.feature_names
        }
        joblib.dump(payload, model_path, compress=3)

        metadata = {
            "model_type": "IsolationForest",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scaler_mean": list(self.scaler.mean_) if hasattr(self.scaler, "mean_") else [],
            "scaler_scale": list(self.scaler.scale_) if hasattr(self.scaler, "scale_") else []
        }

        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"[+] Model pipeline saved -> {model_path}")
        print(f"[+] Metadata exported   -> {metadata_path}")

    @classmethod
    def load(
        cls,
        model_path: str = "models/isolation_forest.joblib",
        metadata_path: Optional[str] = "models/model_metadata.json"
    ) -> "CANIsolationForestModel":
        """
        Load serialized model pipeline and metadata from disk.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        payload = joblib.load(model_path)
        instance = cls()
        instance.scaler = payload["scaler"]
        instance.model = payload["model"]
        instance.threshold = payload.get("threshold", 0.0)
        instance.feature_names = payload.get("feature_names", FEATURE_COLUMNS)
        instance.is_trained = True
        return instance


def train_pipeline(
    normal_csv: str = "dataset/normal_traffic.csv",
    attack_csv: Optional[str] = "dataset/attack_traffic.csv",
    model_output: str = "models/isolation_forest.joblib",
    meta_output: str = "models/model_metadata.json"
) -> Tuple[CANIsolationForestModel, Dict[str, Any]]:
    """
    Execute full training workflow: feature extraction, model fitting, validation, and export.
    """
    print(f"[*] Loading baseline normal dataset: {normal_csv}...")
    X_train, y_train, _ = extract_features_from_csv(normal_csv)
    print(f"[+] Extracted {len(X_train)} normal feature vectors.")

    model = CANIsolationForestModel(n_estimators=150, contamination=0.03, random_state=42)
    start_t = time.time()
    model.fit(X_train)
    train_duration = time.time() - start_t
    print(f"[+] Model trained in {train_duration:.3f}s. Decision threshold: {model.threshold:.6f}")

    metrics: Dict[str, Any] = {}
    if attack_csv and os.path.exists(attack_csv):
        print(f"[*] Evaluating on labeled attack dataset: {attack_csv}...")
        X_test, y_test, _ = extract_features_from_csv(attack_csv)
        metrics = model.evaluate(X_test, y_test)
        print(f"[+] Evaluation Metrics:")
        print(f"    - Precision : {metrics['precision'] * 100:.2f}%")
        print(f"    - Recall    : {metrics['recall'] * 100:.2f}%")
        print(f"    - F1-Score  : {metrics['f1_score'] * 100:.2f}%")
        print(f"    - Accuracy  : {metrics['accuracy'] * 100:.2f}%")
        print(f"    - True Positives (Attacks Caught) : {metrics['true_positives']} / {metrics['true_positives'] + metrics['false_negatives']}")
        print(f"    - False Positives (Normal Flagged): {metrics['false_positives']}")

    model.save(model_output, meta_output)
    return model, metrics


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train CAN-Sentinel Isolation Forest IDS Model")
    parser.add_argument("--train", default="dataset/normal_traffic.csv", help="Path to normal baseline CSV")
    parser.add_argument("--eval", default="dataset/attack_traffic.csv", help="Path to labeled attack evaluation CSV")
    parser.add_argument("--output", default="models/isolation_forest.joblib", help="Output model path")
    parser.add_argument("--meta", default="models/model_metadata.json", help="Output metadata path")
    args = parser.parse_args()

    train_pipeline(args.train, args.eval, args.output, args.meta)
