"""
Heuristic Scoring, Node Localization, and Forensic Alert Engine.
Phase 3, Day 14: Anomaly Alerting & Node Isolation Engine

Pinpoints rogue arbitration IDs, maps compromised ECU nodes, calculates threat severity,
and writes structured forensic alert event logs to logs/alerts.json.
"""

import os
import json
import time
from collections import deque
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Callable

from .stream_detector import DetectionResult
from ..sim.ecu_generator import (
    CAN_ID_BRAKE_OVERRIDE,
    CAN_ID_ENGINE_RPM,
    CAN_ID_VEHICLE_SPEED,
    CAN_ID_ENGINE_TEMP,
    CAN_ID_TRANSMISSION,
    CAN_ID_BODY_DOORS,
    CAN_ID_BODY_CLIMATE,
    CAN_ID_LIGHTING
)

ECU_SUBSYSTEM_MAP = {
    CAN_ID_BRAKE_OVERRIDE: {"subsystem": "Braking & Stability Control", "node": "Brake ECU (0x0A0)", "criticality": "CRITICAL"},
    CAN_ID_ENGINE_RPM:     {"subsystem": "Powertrain Engine",          "node": "Engine ECU (0x110)", "criticality": "HIGH"},
    CAN_ID_VEHICLE_SPEED:  {"subsystem": "Chassis & Speedometer",      "node": "Speed ECU (0x120)",  "criticality": "HIGH"},
    CAN_ID_ENGINE_TEMP:    {"subsystem": "Engine Thermal Management",  "node": "Temp ECU (0x130)",   "criticality": "MEDIUM"},
    CAN_ID_TRANSMISSION:   {"subsystem": "Drivetrain & Gearbox",       "node": "Trans ECU (0x180)",  "criticality": "HIGH"},
    CAN_ID_BODY_DOORS:     {"subsystem": "Body & Security",            "node": "Body ECU (0x230)",   "criticality": "MEDIUM"},
    CAN_ID_BODY_CLIMATE:   {"subsystem": "Interior Climate",           "node": "HVAC ECU (0x240)",   "criticality": "LOW"},
    CAN_ID_LIGHTING:       {"subsystem": "External Lighting",          "node": "Lighting (0x270)",   "criticality": "LOW"},
}

@dataclass
class SecurityAlert:
    """Structured security alert event."""
    alert_id: str
    timestamp: float
    timestamp_iso: str
    can_id: int
    can_id_hex: str
    target_node: str
    target_subsystem: str
    attack_type: str
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    anomaly_score: float
    threat_density_pct: float
    payload_hex: str
    entropy: float
    delta_t_ms: float
    evidence: str
    recommended_mitigation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlertEngine:
    """
    Heuristic rule and scoring engine that analyzes anomalous detections,
    pinpoints attacker source/target, and persists forensic logs.
    """

    def __init__(
        self,
        log_filepath: str = "logs/alerts.json",
        max_history: int = 100
    ):
        self.log_filepath = log_filepath
        self.max_history = max_history
        self.recent_alerts: deque[SecurityAlert] = deque(maxlen=max_history)
        self._alert_callbacks: List[Callable[[SecurityAlert], None]] = []
        self.alert_counter = 0

        # Ensure logs directory exists
        os.makedirs(os.path.dirname(os.path.abspath(log_filepath)), exist_ok=True)

    def add_alert_callback(self, callback: Callable[[SecurityAlert], None]) -> None:
        """Register a callback for real-time visual/countermeasure alerts."""
        self._alert_callbacks.append(callback)

    def evaluate_detection(self, detection: DetectionResult) -> Optional[SecurityAlert]:
        """
        Evaluate a single detection result and generate a SecurityAlert if an intrusion is confirmed.
        """
        if not detection.is_anomaly:
            return None

        self.alert_counter += 1
        can_id = detection.frame.can_id
        payload_hex = detection.parsed.payload_hex
        entropy = detection.parsed.entropy
        delta_t_ms = detection.parsed.delta_t * 1000.0

        # Subsystem mapping
        subsystem_info = ECU_SUBSYSTEM_MAP.get(can_id, {
            "subsystem": "Unauthorized / External Bus Node",
            "node": f"Rogue ID 0x{can_id:03X}",
            "criticality": "HIGH"
        })

        # Heuristic Attack Classification
        if can_id == 0x000 or delta_t_ms < 0.8:
            attack_type = "DOS_BUS_FLOOD"
            severity = "CRITICAL"
            evidence = f"Ultra-high transmission rate detected (Δt = {delta_t_ms:.2f} ms). Bus arbitration monopolized."
            mitigation = "Activate CAN Bus-Off error frame barrier; isolate rogue gateway node."

        elif entropy > 2.75:
            attack_type = "PAYLOAD_FUZZING_ATTACK"
            severity = "HIGH"
            evidence = f"Abnormal payload byte Shannon entropy (H = {entropy:.2f} bits). Random diagnostic fuzzing detected."
            mitigation = "Filter unauthorized diagnostic packets; rate-limit non-essential frames."

        elif can_id == CAN_ID_BRAKE_OVERRIDE:
            attack_type = "CRITICAL_BRAKE_SPOOFING"
            severity = "CRITICAL"
            evidence = f"Spoofed Brake ECU frame detected with irregular timing or unexpected brake override state."
            mitigation = "Trigger ABS failsafe lock; suppress rogue 0x0A0 arbitration slot."

        elif can_id == CAN_ID_ENGINE_RPM:
            attack_type = "ENGINE_POWERTRAIN_SPOOFING"
            severity = "HIGH"
            evidence = f"Inconsistent engine RPM/throttle telemetry sequence detected."
            mitigation = "Cross-validate RPM signal against wheel speeds."

        elif can_id not in ECU_SUBSYSTEM_MAP:
            attack_type = "UNAUTHORIZED_ARBITRATION_ID"
            severity = "HIGH"
            evidence = f"Unregistered CAN arbitration identifier 0x{can_id:03X} transmitting onto vehicle bus."
            mitigation = "Enforce hardware CAN acceptance ID whitelist."

        else:
            attack_type = "STATISTICAL_TIMING_ANOMALY"
            severity = subsystem_info["criticality"]
            evidence = f"Isolation Forest anomaly score ({detection.anomaly_score:.4f}) breached baseline confidence threshold."
            mitigation = "Log forensic frame and verify ECU clock synchronization."

        alert = SecurityAlert(
            alert_id=f"ALERT-{self.alert_counter:06d}",
            timestamp=detection.timestamp,
            timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(detection.timestamp)),
            can_id=can_id,
            can_id_hex=f"0x{can_id:03X}",
            target_node=subsystem_info["node"],
            target_subsystem=subsystem_info["subsystem"],
            attack_type=attack_type,
            severity=severity,
            anomaly_score=round(detection.anomaly_score, 6),
            threat_density_pct=round(detection.threat_density, 2),
            payload_hex=payload_hex,
            entropy=round(entropy, 4),
            delta_t_ms=round(delta_t_ms, 3),
            evidence=evidence,
            recommended_mitigation=mitigation
        )

        self._record_alert(alert)

        # Dispatch to callbacks
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                print(f"[!] Warning in alert callback: {e}")

        return alert

    def _record_alert(self, alert: SecurityAlert) -> None:
        """Append alert to memory buffer and JSON log file."""
        self.recent_alerts.append(alert)

        try:
            with open(self.log_filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception as e:
            print(f"[!] Warning: Failed to write to {self.log_filepath}: {e}")
