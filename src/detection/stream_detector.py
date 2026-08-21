"""
Streaming Real-Time Anomaly Detection Engine.
Phase 3, Day 13: Streaming Real-Time Inference Pipeline

Subscribes to live CAN telemetry streams (IPC socket or Virtual Bus),
extracts rolling temporal & statistical features on-the-fly,
and evaluates the serialized Isolation Forest model in sub-millisecond real time.
"""

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple, Dict, Any

from ..sim.bus_emulator import CANFrame
from ..parser.telemetry_parser import CANTelemetryParser, ParsedTelemetry
from ..ml.features import StreamingFeatureExtractor, FEATURE_COLUMNS
from ..ml.train_isolation_forest import CANIsolationForestModel
from ..ml.model_manager import ModelManager

@dataclass
class DetectionResult:
    """Detection output for a single streaming CAN frame."""
    frame: CANFrame
    parsed: ParsedTelemetry
    is_anomaly: bool
    anomaly_score: float
    threat_density: float # Rolling percentage of anomalies in recent window (0-100%)
    inference_time_us: float
    timestamp: float


class StreamAnomalyDetector:
    """
    Ultra-low-latency real-time inference processor.
    """

    def __init__(
        self,
        model: Optional[CANIsolationForestModel] = None,
        sliding_window_size: int = 50,
        threat_window_size: int = 20
    ):
        self.parser = CANTelemetryParser()
        self.feature_extractor = StreamingFeatureExtractor(window_size=sliding_window_size)
        self.model = model if model is not None else ModelManager.get_or_train_model()

        self.threat_window = deque(maxlen=threat_window_size)
        self._callbacks: List[Callable[[DetectionResult], None]] = []

        self.total_processed = 0
        self.total_anomalies_flagged = 0

    def add_detection_callback(self, callback: Callable[[DetectionResult], None]) -> None:
        """Subscribe to every processed frame result."""
        self._callbacks.append(callback)

    def process_frame(self, frame: CANFrame) -> DetectionResult:
        """
        Process a single incoming frame with sub-millisecond feature extraction and inference.
        """
        t_start = time.perf_counter_ns()

        # 1. Parse and extract telemetry signals
        parsed = self.parser.parse_frame(frame)

        # 2. Extract rolling feature vector
        features = self.feature_extractor.extract_features(
            can_id=frame.can_id,
            dlc=frame.dlc,
            data=frame.data,
            timestamp=frame.timestamp
        )

        # 3. Predict with Isolation Forest
        pred, score = self.model.predict_single(features)
        is_anomaly = (pred == -1)

        # 4. Update rolling threat density (percentage of anomalies in last N frames)
        self.threat_window.append(1 if is_anomaly else 0)
        threat_density = (sum(self.threat_window) / len(self.threat_window)) * 100.0

        t_end = time.perf_counter_ns()
        inference_time_us = (t_end - t_start) / 1000.0

        self.total_processed += 1
        if is_anomaly:
            self.total_anomalies_flagged += 1

        result = DetectionResult(
            frame=frame,
            parsed=parsed,
            is_anomaly=is_anomaly,
            anomaly_score=score,
            threat_density=threat_density,
            inference_time_us=inference_time_us,
            timestamp=frame.timestamp
        )

        # Dispatch result to subscribers
        for cb in self._callbacks:
            try:
                cb(result)
            except Exception as e:
                print(f"[!] Warning in detection callback: {e}")

        return result
