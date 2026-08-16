"""
Unit tests for Multi-ECU Simulation and Timing Verification.
Phase 1, Day 3 Verification
"""

import unittest
import struct
import time
from src.sim.bus_emulator import CANFrame, VirtualCANBus
from src.sim.ecu_generator import (
    VehicleECUSimulator,
    CAN_ID_ENGINE_RPM,
    CAN_ID_VEHICLE_SPEED,
    CAN_ID_ENGINE_TEMP,
    CAN_ID_TRANSMISSION,
    CAN_ID_BRAKE_OVERRIDE,
    CAN_ID_BODY_DOORS,
    CAN_ID_BODY_CLIMATE,
    CAN_ID_LIGHTING
)

class TestMultiECUSimulation(unittest.TestCase):
    """Verify ECU frame generation, signal decoding, and inter-arrival timing."""

    def test_batch_generation_counts_and_types(self):
        sim = VehicleECUSimulator()
        frames = sim.generate_batch(duration_sec=2.0)
        self.assertGreater(len(frames), 200)

        # Verify presence of all expected ECU arbitration IDs
        seen_ids = set(f.can_id for f in frames)
        expected_ids = {
            CAN_ID_ENGINE_RPM,
            CAN_ID_VEHICLE_SPEED,
            CAN_ID_ENGINE_TEMP,
            CAN_ID_TRANSMISSION,
            CAN_ID_BRAKE_OVERRIDE,
            CAN_ID_BODY_DOORS,
            CAN_ID_BODY_CLIMATE,
            CAN_ID_LIGHTING
        }
        self.assertTrue(expected_ids.issubset(seen_ids))

    def test_engine_rpm_payload_encoding(self):
        sim = VehicleECUSimulator()
        frames = sim.generate_batch(duration_sec=1.0)
        rpm_frames = [f for f in frames if f.can_id == CAN_ID_ENGINE_RPM]

        self.assertGreater(len(rpm_frames), 0)
        for frame in rpm_frames:
            self.assertEqual(frame.dlc, 4)
            rpm_val, throttle, status = struct.unpack(">HBB", frame.data[:4])
            self.assertGreaterEqual(rpm_val, 750)
            self.assertLessEqual(rpm_val, 7000)
            self.assertEqual(status, 0x01)

    def test_brake_abs_frequency_and_dlc(self):
        sim = VehicleECUSimulator()
        frames = sim.generate_batch(duration_sec=1.0)
        brake_frames = [f for f in frames if f.can_id == CAN_ID_BRAKE_OVERRIDE]

        # In 1 second @ 10ms period, should have ~100 frames
        self.assertGreaterEqual(len(brake_frames), 90)
        for frame in brake_frames:
            self.assertEqual(frame.dlc, 6)

    def test_live_streaming_callbacks(self):
        bus = VirtualCANBus()
        sim = VehicleECUSimulator(bus=bus)
        received_frames = []

        sim.add_frame_callback(lambda f: received_frames.append(f))
        sim.start()
        time.sleep(0.3) # Run live for 300ms
        sim.stop()

        self.assertGreater(len(received_frames), 10)
        self.assertTrue(any(f.can_id == CAN_ID_ENGINE_RPM for f in received_frames))

if __name__ == "__main__":
    unittest.main()
