"""
CAN Telemetry Feature Engineering and Preprocessing Pipeline.
Phase 2, Day 7: Dataset Preprocessing & Feature Extraction

Extracts temporal, statistical, and information-theoretic features from CAN frames:
- Inter-arrival delta time (Δt per-ID and global)
- Sliding-window message frequency and ratio
- Payload byte Shannon entropy (H(X))
- Byte-level statistical moments (mean, variance)
- Sequential payload change rate (Hamming distance)
"""

import math
import numpy as np
from collections import Counter, deque
from typing import Dict, List, Optional, Tuple, Any

FEATURE_COLUMNS = [
    "can_id",
    "dlc",
    "delta_t",
    "global_delta_t",
    "entropy",
    "byte_mean",
    "byte_variance",
    "id_freq_window",
    "id_ratio_window",
    "payload_change_rate"
]

class FeatureExtractor:
    """
    Computes statistical and information-theoretic features for CAN telemetry frames.
    """

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon Entropy of payload bytes:
        H(X) = - sum(P(x) * log2(P(x)))
        """
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def calculate_byte_stats(data: bytes, dlc: int) -> Tuple[float, float]:
        """Calculate mean and variance of payload bytes."""
        if not data or dlc == 0:
            return 0.0, 0.0
        valid_bytes = list(data[:dlc])
        mean_val = float(np.mean(valid_bytes))
        var_val = float(np.var(valid_bytes))
        return mean_val, var_val

    @staticmethod
    def calculate_payload_change_rate(curr_data: bytes, prev_data: Optional[bytes]) -> float:
        """Count number of differing bytes between consecutive frames with same ID."""
        if prev_data is None:
            return 0.0
        min_len = min(len(curr_data), len(prev_data))
        changes = sum(1 for i in range(min_len) if curr_data[i] != prev_data[i])
        changes += abs(len(curr_data) - len(prev_data))
        return float(changes)


class StreamingFeatureExtractor:
    """
    Stateful feature extractor designed for sub-millisecond real-time streaming inference
    and sliding-window frequency estimation.
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.window = deque(maxlen=window_size)
        self.last_timestamp_per_id: Dict[int, float] = {}
        self.last_payload_per_id: Dict[int, bytes] = {}
        self.last_global_timestamp: Optional[float] = None

    def reset(self) -> None:
        """Reset internal history and window buffers."""
        self.window.clear()
        self.last_timestamp_per_id.clear()
        self.last_payload_per_id.clear()
        self.last_global_timestamp = None

    def extract_features(
        self,
        can_id: int,
        dlc: int,
        data: bytes,
        timestamp: float
    ) -> np.ndarray:
        """
        Extract a 1D numeric feature vector for an incoming CAN frame.
        Returns array matching FEATURE_COLUMNS.
        """
        # 1. Delta times (Δt)
        if can_id in self.last_timestamp_per_id:
            delta_t = max(0.0, timestamp - self.last_timestamp_per_id[can_id])
        else:
            delta_t = 0.0
        self.last_timestamp_per_id[can_id] = timestamp

        if self.last_global_timestamp is not None:
            global_delta_t = max(0.0, timestamp - self.last_global_timestamp)
        else:
            global_delta_t = 0.0
        self.last_global_timestamp = timestamp

        # 2. Entropy and byte statistics
        entropy = FeatureExtractor.calculate_shannon_entropy(data[:dlc])
        byte_mean, byte_var = FeatureExtractor.calculate_byte_stats(data, dlc)

        # 3. Payload change rate compared to previous frame with same ID
        prev_payload = self.last_payload_per_id.get(can_id)
        change_rate = FeatureExtractor.calculate_payload_change_rate(data[:dlc], prev_payload)
        self.last_payload_per_id[can_id] = bytes(data[:dlc])

        # 4. Sliding-window frequency and ratio
        self.window.append(can_id)
        id_freq = self.window.count(can_id)
        id_ratio = float(id_freq) / len(self.window) if len(self.window) > 0 else 0.0

        feature_vector = np.array([
            float(can_id),
            float(dlc),
            float(delta_t),
            float(global_delta_t),
            float(entropy),
            float(byte_mean),
            float(byte_var),
            float(id_freq),
            float(id_ratio),
            float(change_rate)
        ], dtype=np.float64)

        return feature_vector


def extract_features_from_csv(csv_path: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Load a CSV dataset and transform it into a normalized feature matrix X and label vector y.
    Works with standard CSV reader or Pandas.
    """
    import csv

    X_list = []
    y_list = []
    extractor = StreamingFeatureExtractor(window_size=50)

    with open(csv_path, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            can_id = int(row["can_id"])
            dlc = int(row["dlc"])
            ts = float(row["timestamp"])
            label = row.get("label", "NORMAL")

            # Parse hex payload
            hex_str = row.get("payload_hex", "")
            raw_bytes = bytes.fromhex(hex_str) if hex_str else b""

            feat_vec = extractor.extract_features(can_id, dlc, raw_bytes, ts)
            X_list.append(feat_vec)
            y_list.append(label)

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list)
    return X, y, FEATURE_COLUMNS
