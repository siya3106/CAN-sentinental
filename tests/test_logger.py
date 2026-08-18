"""
Unit tests for Forensic CSV Data Logger.
Phase 1, Day 5 Verification
"""

import os
import csv
import tempfile
import unittest
from src.sim.bus_emulator import CANFrame
from src.logger.csv_logger import CSVTelemetryLogger, generate_baseline_dataset

class TestCSVTelemetryLogger(unittest.TestCase):
    """Test CSV file initialization, schema, buffering, and dataset generation."""

    def test_csv_logging_and_schema(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            logger = CSVTelemetryLogger(tmp_path, buffer_size=2)
            f1 = CANFrame(0x110, b'\x09\xC4\x28\x01', dlc=4, timestamp=1000.0)
            f2 = CANFrame(0x120, b'\x19\x64', dlc=2, timestamp=1000.05)

            logger.log_frame(f1, label="NORMAL")
            logger.log_frame(f2, label="NORMAL")
            logger.close()

            # Read back CSV
            with open(tmp_path, mode="r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["can_id_hex"], "0x110")
            self.assertEqual(rows[0]["dlc"], "4")
            self.assertEqual(rows[0]["label"], "NORMAL")
            self.assertEqual(rows[1]["can_id_hex"], "0x120")
            self.assertEqual(rows[1]["dlc"], "2")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_baseline_dataset_generation(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            count = generate_baseline_dataset(output_path=tmp_path, duration_sec=1.0)
            self.assertGreater(count, 100)
            self.assertTrue(os.path.exists(tmp_path))
            self.assertGreater(os.path.getsize(tmp_path), 1000)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
