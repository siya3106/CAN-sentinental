"""
Comprehensive Model Evaluation and Attack Validation Suite.
Phase 2, Day 9: Attack Validation & Evaluation

Evaluates unsupervised Isolation Forest intrusion detection performance
across multi-vector attack scenarios (DoS flooding, Brake spoofing, Engine cutoff, Fuzzing)
and computes classification metrics, confusion matrices, and score separations.
"""

import os
import json
import time
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from .features import extract_features_from_csv
from .train_isolation_forest import CANIsolationForestModel

class ModelEvaluator:
    """
    Evaluator for CAN-Sentinel Anomaly Detection Models.
    """

    def __init__(self, model: CANIsolationForestModel):
        self.model = model

    def evaluate_dataset(self, test_csv_path: str) -> Dict[str, Any]:
        """
        Evaluate model against a labeled evaluation dataset and calculate
        global and per-attack-class metrics.
        """
        if not os.path.exists(test_csv_path):
            raise FileNotFoundError(f"Evaluation dataset not found: {test_csv_path}")

        X, y_labels, feature_names = extract_features_from_csv(test_csv_path)
        predictions, scores = self.model.predict(X)

        # Ground truth: 1 for NORMAL, -1 for any attack
        y_true_binary = np.where(y_labels == "NORMAL", 1, -1)

        # Global Confusion Matrix
        tp = int(np.sum((y_true_binary == -1) & (predictions == -1)))
        fp = int(np.sum((y_true_binary == 1) & (predictions == -1)))
        tn = int(np.sum((y_true_binary == 1) & (predictions == 1)))
        fn = int(np.sum((y_true_binary == -1) & (predictions == 1)))

        total = len(y_true_binary)
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1_score = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = float((tp + tn) / total) if total > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        # Score distributions
        normal_scores = scores[y_true_binary == 1]
        attack_scores = scores[y_true_binary == -1]

        mean_normal_score = float(np.mean(normal_scores)) if len(normal_scores) > 0 else 0.0
        mean_attack_score = float(np.mean(attack_scores)) if len(attack_scores) > 0 else 0.0
        score_gap = mean_normal_score - mean_attack_score

        # Per-Attack Class Breakdown
        unique_labels = sorted(list(set(y_labels)))
        per_class_metrics: Dict[str, Dict[str, Any]] = {}

        for label in unique_labels:
            if label == "NORMAL":
                continue
            mask = (y_labels == label)
            class_count = int(np.sum(mask))
            caught = int(np.sum((mask) & (predictions == -1)))
            detection_rate = float(caught / class_count) if class_count > 0 else 0.0
            avg_score = float(np.mean(scores[mask])) if class_count > 0 else 0.0

            per_class_metrics[label] = {
                "total_frames": class_count,
                "detected_anomalies": caught,
                "detection_rate_pct": round(detection_rate * 100.0, 2),
                "mean_anomaly_score": round(avg_score, 6)
            }

        report = {
            "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dataset_path": test_csv_path,
            "total_frames_evaluated": total,
            "decision_threshold": round(self.model.threshold, 6),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn
            },
            "global_metrics": {
                "precision_pct": round(precision * 100.0, 2),
                "recall_pct": round(recall * 100.0, 2),
                "f1_score_pct": round(f1_score * 100.0, 2),
                "accuracy_pct": round(accuracy * 100.0, 2),
                "false_positive_rate_pct": round(fpr * 100.0, 2)
            },
            "score_distribution": {
                "mean_normal_score": round(mean_normal_score, 6),
                "mean_attack_score": round(mean_attack_score, 6),
                "score_separation_gap": round(score_gap, 6)
            },
            "per_attack_vector_breakdown": per_class_metrics
        }

        return report


def print_evaluation_report(report: Dict[str, Any]) -> None:
    """Format and print evaluation results to terminal."""
    gm = report["global_metrics"]
    cm = report["confusion_matrix"]
    sd = report["score_distribution"]

    print("\n" + "=" * 65)
    print("       CAN-Sentinel: Intrusion Detection Evaluation Audit")
    print("=" * 65)
    print(f"[*] Total Frames Evaluated : {report['total_frames_evaluated']}")
    print(f"[*] Decision Threshold     : {report['decision_threshold']}")
    print("-" * 65)
    print(" GLOBAL CLASSIFICATION METRICS:")
    print(f"  - Precision (PPV)        : {gm['precision_pct']}%")
    print(f"  - Recall (Sensitivity)   : {gm['recall_pct']}%")
    print(f"  - F1-Score               : {gm['f1_score_pct']}%")
    print(f"  - Accuracy               : {gm['accuracy_pct']}%")
    print(f"  - False Positive Rate    : {gm['false_positive_rate_pct']}%")
    print("-" * 65)
    print(" CONFUSION MATRIX:")
    print(f"  - True Positives (TP)    : {cm['true_positives']} (Attacks Caught)")
    print(f"  - False Positives (FP)   : {cm['false_positives']} (Normal False Alarms)")
    print(f"  - True Negatives (TN)    : {cm['true_negatives']} (Normal Clean Passes)")
    print(f"  - False Negatives (FN)   : {cm['false_negatives']} (Missed Attacks)")
    print("-" * 65)
    print(" SCORE SEPARATION DYNAMICS:")
    print(f"  - Mean Normal Score      : {sd['mean_normal_score']}")
    print(f"  - Mean Attack Score      : {sd['mean_attack_score']}")
    print(f"  - Anomaly Separation Gap : {sd['score_separation_gap']}")
    print("-" * 65)
    print(" PER-ATTACK VECTOR DETECTION RATES:")
    for attack_name, data in report["per_attack_vector_breakdown"].items():
        print(f"  - {attack_name:<20} : {data['detection_rate_pct']}% ({data['detected_anomalies']}/{data['total_frames']}) [Mean Score: {data['mean_anomaly_score']}]")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate CAN-Sentinel Model Performance")
    parser.add_argument("--eval-csv", default="dataset/attack_traffic.csv", help="Path to labeled evaluation CSV")
    parser.add_argument("--train-csv", default="dataset/normal_traffic.csv", help="Path to baseline normal CSV for training")
    parser.add_argument("--export-report", default="logs/evaluation_report.json", help="Path to export evaluation JSON")
    args = parser.parse_args()

    # Load baseline, train model, evaluate
    from .train_isolation_forest import train_pipeline
    model, _ = train_pipeline(normal_csv=args.train_csv, attack_csv=args.eval_csv)

    evaluator = ModelEvaluator(model)
    report = evaluator.evaluate_dataset(args.eval_csv)
    print_evaluation_report(report)

    if args.export_report:
        os.makedirs(os.path.dirname(os.path.abspath(args.export_report)), exist_ok=True)
        with open(args.export_report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Evaluation report exported to {args.export_report}")
