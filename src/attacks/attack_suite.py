"""
Automotive CAN Bus Attack Injection Suite (Python Engine).
Phase 2, Day 6: Malware Injection & Attack Simulation

Provides programmatic injection of Denial of Service (DoS) flooding,
critical ECU spoofing (Brake Override, Engine Cutoff), and payload fuzzing.
Also generates labeled forensic attack datasets for Isolation Forest training and validation.
"""

import os
import time
import random
import struct
from typing import List, Optional, Dict, Any, Callable
from ..sim.bus_emulator import CANFrame, VirtualCANBus
from ..sim.ecu_generator import (
    VehicleECUSimulator,
    CAN_ID_BRAKE_OVERRIDE,
    CAN_ID_ENGINE_RPM,
    CAN_ID_VEHICLE_SPEED
)
from ..parser.telemetry_parser import CANTelemetryParser
from ..logger.csv_logger import CSVTelemetryLogger

class CANAttackSuite:
    """
    Automotive malware and intrusion simulation suite.
    """

    @staticmethod
    def craft_flood_frame(target_id: int = 0x000) -> CANFrame:
        """Craft a dominant high-priority frame for DoS bus starvation."""
        payload = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        return CANFrame(can_id=target_id, data=payload, dlc=8, timestamp=time.time())

    @staticmethod
    def craft_spoof_brake_frame(brake_pct: int = 100, abs_active: bool = True) -> CANFrame:
        """Craft a spoofed Brake / ABS ECU override frame."""
        payload = struct.pack("BBBBBB", brake_pct, 1 if abs_active else 0, 0, 0, 0, 0)
        return CANFrame(can_id=CAN_ID_BRAKE_OVERRIDE, data=payload, dlc=6, timestamp=time.time())

    @staticmethod
    def craft_spoof_engine_kill_frame() -> CANFrame:
        """Craft a spoofed Engine ECU frame reporting sudden engine cutoff (0 RPM)."""
        payload = struct.pack(">HBB", 0, 0, 0)
        return CANFrame(can_id=CAN_ID_ENGINE_RPM, data=payload, dlc=4, timestamp=time.time())

    @staticmethod
    def craft_fuzzing_frame() -> CANFrame:
        """Craft a randomized CAN frame with random ID and random high-entropy payload."""
        rand_id = random.randint(0x001, 0x7FE)
        dlc = random.randint(1, 8)
        data = bytes(random.randint(0, 255) for _ in range(dlc))
        return CANFrame(can_id=rand_id, data=data, dlc=dlc, timestamp=time.time())

    @classmethod
    def inject_dos_flood(
        cls,
        bus: VirtualCANBus,
        count: int = 500,
        rate_hz: float = 2000.0,
        target_id: int = 0x000,
        callback: Optional[Callable[[CANFrame], None]] = None
    ) -> List[CANFrame]:
        """Execute a high-frequency DoS packet flood."""
        injected: List[CANFrame] = []
        interval = 1.0 / rate_hz if rate_hz > 0 else 0.0005

        for _ in range(count):
            frame = cls.craft_flood_frame(target_id=target_id)
            bus.send(frame)
            injected.append(frame)
            if callback:
                callback(frame)
            if interval > 0:
                time.sleep(interval)

        return injected

    @classmethod
    def inject_spoof_brake(
        cls,
        bus: VirtualCANBus,
        count: int = 100,
        rate_hz: float = 100.0,
        callback: Optional[Callable[[CANFrame], None]] = None
    ) -> List[CANFrame]:
        """Inject spoofed brake override frames."""
        injected: List[CANFrame] = []
        interval = 1.0 / rate_hz if rate_hz > 0 else 0.01

        for _ in range(count):
            frame = cls.craft_spoof_brake_frame(brake_pct=100, abs_active=True)
            bus.send(frame)
            injected.append(frame)
            if callback:
                callback(frame)
            if interval > 0:
                time.sleep(interval)

        return injected

    @classmethod
    def inject_fuzzing(
        cls,
        bus: VirtualCANBus,
        count: int = 200,
        rate_hz: float = 500.0,
        callback: Optional[Callable[[CANFrame], None]] = None
    ) -> List[CANFrame]:
        """Inject randomized fuzzing frames."""
        injected: List[CANFrame] = []
        interval = 1.0 / rate_hz if rate_hz > 0 else 0.002

        for _ in range(count):
            frame = cls.craft_fuzzing_frame()
            bus.send(frame)
            injected.append(frame)
            if callback:
                callback(frame)
            if interval > 0:
                time.sleep(interval)

        return injected


def generate_labeled_attack_dataset(
    output_path: str = "dataset/attack_traffic.csv",
    total_duration_sec: float = 30.0
) -> int:
    """
    Generate a labeled forensic dataset containing normal driving telemetry
    interleaved with distinct attack intervals (DoS flood, Brake spoofing, Fuzzing).
    """
    print(f"[*] Generating labeled attack dataset -> {output_path} (Duration: {total_duration_sec}s)...")
    sim = VehicleECUSimulator()
    normal_frames = sim.generate_batch(duration_sec=total_duration_sec)

    logger = CSVTelemetryLogger(output_path, buffer_size=500)
    base_time = 1000000.0

    # Build chronological timeline with attack bursts injected at scheduled intervals:
    # 0s - 8s   : Normal traffic
    # 8s - 12s  : DoS Flood attack (ID 0x000 @ 2500 fps)
    # 12s - 18s : Normal traffic
    # 18s - 22s : Spoofed Brake Override attack (ID 0x0A0 @ 200 fps)
    # 22s - 26s : Normal traffic
    # 26s - 30s : Fuzzing attack (Random IDs & high entropy @ 800 fps)

    all_events: List[tuple[float, CANFrame, str]] = []

    # Add normal frames
    for f in normal_frames:
        all_events.append((f.timestamp, f, "NORMAL"))

    # Add DoS Flood attack frames (t=8s to 12s)
    flood_start = base_time + 8.0
    flood_count = 600
    for i in range(flood_count):
        t = flood_start + (i * 0.006)
        f = CANFrame(0x000, b'\x00\x00\x00\x00\x00\x00\x00\x00', dlc=8, timestamp=t)
        all_events.append((t, f, "ATTACK_FLOOD"))

    # Add Brake Spoofing attack frames (t=18s to 22s)
    spoof_start = base_time + 18.0
    spoof_count = 200
    for i in range(spoof_count):
        t = spoof_start + (i * 0.02)
        f = CANFrame(CAN_ID_BRAKE_OVERRIDE, b'\x64\x01\x00\x00\x00\x00', dlc=6, timestamp=t)
        all_events.append((t, f, "ATTACK_SPOOF_BRAKE"))

    # Add Fuzzing attack frames (t=26s to 30s)
    fuzz_start = base_time + 26.0
    fuzz_count = 300
    for i in range(fuzz_count):
        t = fuzz_start + (i * 0.013)
        rand_id = random.randint(0x001, 0x7FE)
        dlc = random.randint(1, 8)
        data = bytes(random.randint(0, 255) for _ in range(dlc))
        f = CANFrame(rand_id, data, dlc=dlc, timestamp=t)
        all_events.append((t, f, "ATTACK_FUZZING"))

    # Sort all events chronologically by timestamp
    all_events.sort(key=lambda x: x[0])

    # Log to CSV through stateful parser
    for _, frame, label in all_events:
        logger.log_frame(frame, label=label)

    logger.close()
    print(f"[+] Labeled attack dataset generated successfully with {logger.total_logged} frames.")
    return logger.total_logged


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CAN-Sentinel Attack Injection & Dataset Generator")
    parser.add_argument("-o", "--output", default="dataset/attack_traffic.csv", help="Output CSV path")
    parser.add_argument("-d", "--duration", type=float, default=30.0, help="Simulation duration")
    args = parser.parse_args()

    generate_labeled_attack_dataset(args.output, args.duration)
