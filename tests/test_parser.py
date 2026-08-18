"""
Unit tests for CAN Telemetry Parser and Signal Decoder.
Phase 1, Day 4 Verification
"""

import math
import struct
import unittest
from src.sim.bus_emulator import CANFrame
from src.parser.telemetry_parser import (
    CANTelemetryParser,
    CAN_ID_ENGINE_RPM,
    CAN_ID_VEHICLE_SPEED,
    CAN_ID_ENGINE_TEMP,
    CAN_ID_TRANSMISSION,
    CAN_ID_BRAKE_OVERRIDE
)

class TestCANTelemetryParser(unittest.TestCase):
    """Test telemetry parsing, Δt inter-arrival delta times, and entropy calculation."""

    def setUp(self):
        self.parser = CANTelemetryParser()

    def test_inter_arrival_delta_time(self):
        t0 = 1000.000
        t1 = 1000.020
        t2 = 1000.040

        f1 = CANFrame(CAN_ID_ENGINE_RPM, b'\x09\xC4\x28\x01', dlc=4, timestamp=t0)
        f2 = CANFrame(CAN_ID_ENGINE_RPM, b'\x09\xC5\x28\x01', dlc=4, timestamp=t1)
        f3 = CANFrame(CAN_ID_ENGINE_RPM, b'\x09\xC6\x28\x01', dlc=4, timestamp=t2)

        p1 = self.parser.parse_frame(f1)
        self.assertEqual(p1.delta_t, 0.0)

        p2 = self.parser.parse_frame(f2)
        self.assertAlmostEqual(p2.delta_t, 0.020, places=5)

        p3 = self.parser.parse_frame(f3)
        self.assertAlmostEqual(p3.delta_t, 0.020, places=5)

    def test_shannon_entropy_calculation(self):
        # All zeros -> 0 entropy
        entropy_zero = CANTelemetryParser.calculate_shannon_entropy(b'\x00\x00\x00\x00')
        self.assertEqual(entropy_zero, 0.0)

        # High diversity 8 distinct bytes -> log2(8) = 3.0 bits
        entropy_max = CANTelemetryParser.calculate_shannon_entropy(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        self.assertAlmostEqual(entropy_max, 3.0, places=4)

    def test_signal_decoding(self):
        # Engine RPM = 2500 (0x09C4), Throttle = 40%, Running = 1
        payload = struct.pack(">HBB", 2500, 40, 0x01)
        frame = CANFrame(CAN_ID_ENGINE_RPM, payload, dlc=4, timestamp=100.0)
        parsed = self.parser.parse_frame(frame)

        self.assertEqual(parsed.decoded_signals["rpm"], 2500)
        self.assertEqual(parsed.decoded_signals["throttle_pct"], 40)
        self.assertEqual(parsed.decoded_signals["engine_status"], "RUNNING")

        # Vehicle Speed = 65.50 km/h (raw = 6550)
        speed_payload = struct.pack(">H", 6550)
        speed_frame = CANFrame(CAN_ID_VEHICLE_SPEED, speed_payload, dlc=2, timestamp=100.05)
        parsed_speed = self.parser.parse_frame(speed_frame)
        self.assertEqual(parsed_speed.decoded_signals["speed_kmh"], 65.50)

if __name__ == "__main__":
    unittest.main()
