"""
Unit tests for Attack Validation, Evaluation Metrics, and Model Manager.
Phase 2, Day 9 & 10 Verification
"""

import os
import unittest
import tempfile
import numpy as np
from src.ml.features import FEATURE_COLUMNS
from src.ml.train_isolation_forest import CANIsolationForestModel
from src.ml.evaluate import ModelEvaluator
from src.ml.model_manager import ModelManager
from tests.benchmark_latency import benchmark_inference_latency

class TestEvaluationAndAudit(unittest.TestCase):
    """Verify evaluation metric calculations and audit pipeline."""

    def test_evaluation_confusion_matrix(self):
        # Create dummy model
        model = CANIsolationForestModel(n_estimators=30, contamination=0.1, random_state=42)
        X_dummy = np.random.rand(100, len(FEATURE_COLUMNS))
        model.fit(X_dummy)

        # Create synthetic evaluation dataset CSV
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write("timestamp,can_id,can_id_hex,ecu_name,dlc,payload_hex,delta_t,global_delta_t,entropy,byte_0,byte_1,byte_2,byte_3,byte_4,byte_5,byte_6,byte_7,decoded_summary,label\n")
            # Normal frames
            for i in range(50):
                tmp.write(f"1000.{i:03d},272,0x110,Engine,4,09C40100,0.02,0.01,1.5,9,196,1,0,0,0,0,0,rpm=2500,NORMAL\n")
            # Attack frames
            for i in range(20):
                tmp.write(f"1001.{i:03d},0,0x000,Attack,8,0000000000000000,0.0001,0.0001,0.0,0,0,0,0,0,0,0,0,flood,ATTACK_FLOOD\n")

        try:
            evaluator = ModelEvaluator(model)
            report = evaluator.evaluate_dataset(tmp_path)

            self.assertEqual(report["total_frames_evaluated"], 70)
            self.assertIn("global_metrics", report)
            self.assertIn("confusion_matrix", report)
            self.assertIn("ATTACK_FLOOD", report["per_attack_vector_breakdown"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_latency_benchmark_constraint(self):
        results = benchmark_inference_latency(iterations=200)
        self.assertTrue(results["sub_millisecond_verified"])
        self.assertLess(results["p95_latency_us"], 1000.0)

if __name__ == "__main__":
    unittest.main()
