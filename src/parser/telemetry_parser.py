"""
Automotive SocketCAN Telemetry Parser and Signal Decoder.
Phase 1, Day 4: Python SocketCAN Telemetry Parser

Sniffs incoming CAN frames, parses arbitration IDs and payloads,
calculates precise inter-arrival delta times (Δt), computes Shannon entropy,
and decodes domain vehicle ECU telemetry signals.
"""

import math
import time
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Callable, Tuple
from collections import Counter
from ..sim.bus_emulator import CANFrame, VirtualCANBus

# Automotive ECU IDs
CAN_ID_BRAKE_OVERRIDE   = 0x0A0  # 10ms (100 Hz)
CAN_ID_ENGINE_RPM       = 0x110  # 20ms (50 Hz)
CAN_ID_VEHICLE_SPEED    = 0x120  # 50ms (20 Hz)
CAN_ID_ENGINE_TEMP      = 0x130  # 100ms (10 Hz)
CAN_ID_TRANSMISSION     = 0x180  # 50ms (20 Hz)
CAN_ID_BODY_DOORS       = 0x230  # 100ms (10 Hz)
CAN_ID_BODY_CLIMATE     = 0x240  # 200ms (5 Hz)
CAN_ID_LIGHTING         = 0x270  # 100ms (10 Hz)

ECU_NAMES = {
    CAN_ID_BRAKE_OVERRIDE: "Brake/ABS ECU",
    CAN_ID_ENGINE_RPM: "Engine RPM ECU",
    CAN_ID_VEHICLE_SPEED: "Speedometer ECU",
    CAN_ID_ENGINE_TEMP: "Coolant/Oil Temp ECU",
    CAN_ID_TRANSMISSION: "Transmission ECU",
    CAN_ID_BODY_DOORS: "Body Doors ECU",
    CAN_ID_BODY_CLIMATE: "Climate/HVAC ECU",
    CAN_ID_LIGHTING: "Lighting/Signals ECU",
}

@dataclass
class ParsedTelemetry:
    """Structured representation of a parsed CAN telemetry message."""
    timestamp: float
    can_id: int
    can_id_hex: str
    ecu_name: str
    dlc: int
    data: bytes
    payload_hex: str
    delta_t: float               # Per-ID inter-arrival delta time (seconds)
    global_delta_t: float        # Global bus inter-arrival delta time (seconds)
    entropy: float               # Shannon entropy of payload bytes (bits)
    decoded_signals: Dict[str, Any] = field(default_factory=dict)
    is_extended: bool = False
    is_error: bool = False

    def to_flat_dict(self) -> Dict[str, Any]:
        """Convert parsed telemetry into flat tabular format for CSV/DataFrame logging."""
        byte_values = list(self.data[:8]) + [0] * (8 - len(self.data[:8]))
        flat = {
            "timestamp": f"{self.timestamp:.6f}",
            "can_id": self.can_id,
            "can_id_hex": self.can_id_hex,
            "ecu_name": self.ecu_name,
            "dlc": self.dlc,
            "payload_hex": self.payload_hex,
            "delta_t": f"{self.delta_t:.6f}",
            "global_delta_t": f"{self.global_delta_t:.6f}",
            "entropy": f"{self.entropy:.4f}",
            "byte_0": byte_values[0],
            "byte_1": byte_values[1],
            "byte_2": byte_values[2],
            "byte_3": byte_values[3],
            "byte_4": byte_values[4],
            "byte_5": byte_values[5],
            "byte_6": byte_values[6],
            "byte_7": byte_values[7],
            "decoded_summary": self.format_decoded_signals(),
            "label": "NORMAL"
        }
        return flat

    def format_decoded_signals(self) -> str:
        """Create a human-readable summary string of decoded signals."""
        if not self.decoded_signals:
            return "Raw Payload"
        parts = [f"{k}={v}" for k, v in self.decoded_signals.items()]
        return "; ".join(parts)


class CANTelemetryParser:
    """
    Stateful CAN Frame Parser and Feature Extractor.
    Maintains per-ID arrival history to compute rolling inter-arrival delta times (Δt).
    """

    def __init__(self):
        self.last_seen_per_id: Dict[int, float] = {}
        self.last_global_timestamp: Optional[float] = None
        self.message_counts: Dict[int, int] = {}
        self.total_messages: int = 0

    def reset_state(self) -> None:
        """Reset parser timestamp histories and counters."""
        self.last_seen_per_id.clear()
        self.last_global_timestamp = None
        self.message_counts.clear()
        self.total_messages = 0

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

    def decode_signals(self, can_id: int, data: bytes) -> Dict[str, Any]:
        """Decode application-level vehicle signals according to DBC layout."""
        signals: Dict[str, Any] = {}
        dlc = len(data)

        if can_id == CAN_ID_ENGINE_RPM and dlc >= 4:
            rpm, throttle, status = struct.unpack(">HBB", data[:4])
            signals["rpm"] = int(rpm)
            signals["throttle_pct"] = int(throttle)
            signals["engine_status"] = "RUNNING" if status == 1 else "OFF"

        elif can_id == CAN_ID_VEHICLE_SPEED and dlc >= 2:
            speed_raw = struct.unpack(">H", data[:2])[0]
            signals["speed_kmh"] = round(speed_raw / 100.0, 2)

        elif can_id == CAN_ID_ENGINE_TEMP and dlc >= 3:
            temp_raw, oil_press, err = struct.unpack("BBB", data[:3])
            signals["coolant_temp_c"] = int(temp_raw) - 40
            signals["oil_pressure_bar"] = round(oil_press / 10.0, 1)

        elif can_id == CAN_ID_TRANSMISSION and dlc >= 4:
            gear, torque_nm, clutch, _ = struct.unpack(">BHBB", data[:4])
            signals["gear"] = "P/N" if gear == 0 else f"G{gear}"
            signals["torque_nm"] = int(torque_nm)
            signals["clutch"] = "ENGAGED" if clutch == 1 else "DISENGAGED"

        elif can_id == CAN_ID_BRAKE_OVERRIDE and dlc >= 6:
            brake_pct, abs_act, fl, fr, rl, rr = struct.unpack("BBBBBB", data[:6])
            signals["brake_pct"] = int(brake_pct)
            signals["abs_active"] = bool(abs_act)
            signals["wheel_speeds"] = f"[{fl},{fr},{rl},{rr}]"

        elif can_id == CAN_ID_BODY_DOORS and dlc >= 3:
            doors, window, seatbelt = struct.unpack("BBB", data[:3])
            signals["doors_locked"] = bool(doors == 0xFF)
            signals["driver_seatbelt"] = bool(seatbelt == 1)

        elif can_id == CAN_ID_BODY_CLIMATE and dlc >= 4:
            target, ambient, fan, ac = struct.unpack("BBBB", data[:4])
            signals["target_temp_c"] = int(target)
            signals["ambient_temp_c"] = int(ambient)
            signals["fan_speed"] = int(fan)
            signals["ac_on"] = bool(ac == 1)

        elif can_id == CAN_ID_LIGHTING and dlc >= 2:
            lights, turn = struct.unpack("BB", data[:2])
            signals["headlights"] = "ON" if lights == 1 else "OFF"
            signals["turn_signal"] = "NONE" if turn == 0 else ("LEFT" if turn == 1 else "RIGHT")

        return signals

    def parse_frame(self, frame: CANFrame) -> ParsedTelemetry:
        """
        Parse a single CANFrame, calculate Δt inter-arrival time and Shannon entropy,
        and decode domain signals.
        """
        ts = frame.timestamp
        can_id = frame.can_id

        # Calculate per-ID delta time Δt
        if can_id in self.last_seen_per_id:
            delta_t = max(0.0, ts - self.last_seen_per_id[can_id])
        else:
            delta_t = 0.0
        self.last_seen_per_id[can_id] = ts

        # Calculate global delta time Δt
        if self.last_global_timestamp is not None:
            global_delta_t = max(0.0, ts - self.last_global_timestamp)
        else:
            global_delta_t = 0.0
        self.last_global_timestamp = ts

        # Update message statistics
        self.message_counts[can_id] = self.message_counts.get(can_id, 0) + 1
        self.total_messages += 1

        # Entropy & hex formatting
        entropy = self.calculate_shannon_entropy(frame.data[:frame.dlc])
        payload_hex = "".join(f"{b:02X}" for b in frame.data[:frame.dlc])
        can_id_hex = f"0x{can_id:03X}"
        ecu_name = ECU_NAMES.get(can_id, "Unknown ECU")

        # Decode application signals
        decoded_signals = self.decode_signals(can_id, frame.data[:frame.dlc])

        return ParsedTelemetry(
            timestamp=ts,
            can_id=can_id,
            can_id_hex=can_id_hex,
            ecu_name=ecu_name,
            dlc=frame.dlc,
            data=frame.data[:frame.dlc],
            payload_hex=payload_hex,
            delta_t=delta_t,
            global_delta_t=global_delta_t,
            entropy=entropy,
            decoded_signals=decoded_signals,
            is_extended=frame.is_extended,
            is_error=frame.is_error
        )
