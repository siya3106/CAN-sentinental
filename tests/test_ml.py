"""
Unit tests for Feature Extraction and Isolation Forest Model.
Phase 2, Day 7 & 8 Verification
"""

import os
import unittest
import tempfile
import numpy as np
from src.ml.features import (
    FeatureExtractor,
    StreamingFeatureExtractor,
    FEATURE_COLUMNS
)
from src.ml.train_isolation_forest import CANIsolationForestModel

class TestMLPipeline(unittest.TestCase):
    """Test feature extraction, scaling, model fitting, anomaly detection, and serialization."""

    def test_shannon_entropy(self):
        self.assertEqual(FeatureExtractor.calculate_shannon_entropy(b'\x00' * 8), 0.0)
        self.assertAlmostEqual(FeatureExtractor.calculate_shannon_entropy(bytes(range(8))), 3.0, places=4)

    def test_streaming_feature_extractor(self):
        extractor = StreamingFeatureExtractor(window_size=10)
        # Feed 5 frames
        f1 = extractor.extract_features(0x110, 4, b'\x09\xC4\x28\x01', 100.0)
        f2 = extractor.extract_features(0x110, 4, b'\x09\xC5\x28\x01', 100.02)

        self.assertEqual(len(f1), len(FEATURE_COLUMNS))
        self.assertEqual(f1[0], 0x110) # can_id
        self.assertEqual(f1[2], 0.0)   # delta_t first frame
        self.assertAlmostEqual(f2[2], 0.02, places=5) # delta_t second frame
        self.assertEqual(f2[7], 2.0)   # id_freq in window

    def test_isolation_forest_training_and_inference(self):
        # Generate synthetic normal baseline (low variance delta_t, consistent IDs)
        np.random.seed(42)
        normal_data = []
        for i in range(200):
            can_id = float(np.random.choice([0x110, 0x120, 0x180, 0x230]))
            dlc = 4.0
            dt = 0.02 + np.random.normal(0, 0.002)
            global_dt = 0.005 + np.random.normal(0, 0.0005)
            entropy = 1.5 + np.random.normal(0, 0.1)
            b_mean = 50.0 + np.random.normal(0, 5.0)
            b_var = 10.0 + np.random.normal(0, 2.0)
            freq = 10.0 + np.random.normal(0, 2.0)
            ratio = 0.2 + np.random.normal(0, 0.05)
            change = 1.0 + np.random.normal(0, 0.5)
            normal_data.append([can_id, dlc, dt, global_dt, entropy, b_mean, b_var, freq, ratio, change])

        X_train = np.array(normal_data)
        model = CANIsolationForestModel(n_estimators=50, contamination=0.05, random_state=42)
        model.fit(X_train)

        self.assertTrue(model.is_trained)

        # Test normal sample prediction
        normal_sample = np.array([0x110, 4.0, 0.020, 0.005, 1.5, 50.0, 10.0, 10.0, 0.2, 1.0])
        pred_norm, score_norm = model.predict_single(normal_sample)
        self.assertEqual(pred_norm, 1) # Normal

        # Test anomalous DoS flood sample (ID=0x000, Δt=0.0001, ratio=1.0)
        attack_sample = np.array([0x000, 8.0, 0.0001, 0.0001, 0.0, 0.0, 0.0, 50.0, 1.0, 0.0])
        pred_att, score_att = model.predict_single(attack_sample)
        self.assertEqual(pred_att, -1) # Anomaly caught
        self.assertLess(score_att, score_norm)

    def test_model_serialization(self):
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp_model, \
             tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_meta:
            m_path = tmp_model.name
            meta_path = tmp_meta.name

        try:
            X_dummy = np.random.rand(50, len(FEATURE_COLUMNS))
            model = CANIsolationForestModel(n_estimators=20, random_state=42)
            model.fit(X_dummy)
            model.save(m_path, meta_path)

            # Reload
            loaded = CANIsolationForestModel.load(m_path, meta_path)
            self.assertTrue(loaded.is_trained)
            self.assertEqual(loaded.threshold, model.threshold)
        finally:
            if os.path.exists(m_path): os.remove(m_path)
            if os.path.exists(meta_path): os.remove(meta_path)

if __name__ == "__main__":
    unittest.main()
