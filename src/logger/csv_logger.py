"""
Forensic CSV Telemetry Logger for Automotive CAN-Sentinel.
Phase 1, Day 5: Forensic CSV Data Logger

Streams parsed CAN bus telemetry into structured forensic CSV datasets
for baseline vehicle behavior modeling and machine learning feature extraction.
"""

import os
import csv
import time
import threading
from typing import Optional, List, Dict, Any
from ..sim.bus_emulator import CANFrame, VirtualCANBus
from ..sim.ecu_generator import VehicleECUSimulator
from ..parser.telemetry_parser import CANTelemetryParser, ParsedTelemetry

CSV_FIELDNAMES = [
    "timestamp",
    "can_id",
    "can_id_hex",
    "ecu_name",
    "dlc",
    "payload_hex",
    "delta_t",
    "global_delta_t",
    "entropy",
    "byte_0",
    "byte_1",
    "byte_2",
    "byte_3",
    "byte_4",
    "byte_5",
    "byte_6",
    "byte_7",
    "decoded_summary",
    "label"
]

class CSVTelemetryLogger:
    """
    Thread-safe streaming CSV logger for CAN-Sentinel telemetry datasets.
    """

    def __init__(self, filepath: str, buffer_size: int = 100):
        self.filepath = filepath
        self.buffer_size = buffer_size
        self.parser = CANTelemetryParser()
        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._file_handle = None
        self._csv_writer = None
        self.total_logged = 0

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        self._init_file()

    def _init_file(self) -> None:
        """Initialize the CSV file with header schema."""
        file_exists = os.path.exists(self.filepath) and os.path.getsize(self.filepath) > 0
        self._file_handle = open(self.filepath, mode="a", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(self._file_handle, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            self._csv_writer.writeheader()
            self._file_handle.flush()

    def log_frame(self, frame: CANFrame, label: str = "NORMAL") -> ParsedTelemetry:
        """Parse and append a CANFrame to the CSV buffer."""
        parsed = self.parser.parse_frame(frame)
        row = parsed.to_flat_dict()
        row["label"] = label

        with self._lock:
            self._buffer.append(row)
            self.total_logged += 1
            if len(self._buffer) >= self.buffer_size:
                self.flush()

        return parsed

    def flush(self) -> None:
        """Flush buffered rows to disk."""
        if not self._file_handle or not self._buffer:
            return
        self._csv_writer.writerows(self._buffer)
        self._file_handle.flush()
        self._buffer.clear()

    def close(self) -> None:
        """Flush remaining rows and close file handle."""
        with self._lock:
            self.flush()
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def generate_baseline_dataset(
    output_path: str = "dataset/normal_traffic.csv",
    duration_sec: float = 30.0
) -> int:
    """
    Run the multi-ECU simulation and record a baseline normal vehicle telemetry dataset.
    """
    print(f"[*] Generating normal baseline dataset -> {output_path} (Duration: {duration_sec}s)...")
    sim = VehicleECUSimulator()
    frames = sim.generate_batch(duration_sec=duration_sec)

    logger = CSVTelemetryLogger(output_path, buffer_size=500)
    for frame in frames:
        logger.log_frame(frame, label="NORMAL")
    logger.close()

    print(f"[+] Baseline dataset saved successfully with {logger.total_logged} frames.")
    return logger.total_logged


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CAN-Sentinel Forensic CSV Data Logger")
    parser.add_argument("-o", "--output", default="dataset/normal_traffic.csv", help="Output CSV path")
    parser.add_argument("-d", "--duration", type=float, default=30.0, help="Simulation duration in seconds")
    args = parser.parse_args()

    generate_baseline_dataset(args.output, args.duration)
