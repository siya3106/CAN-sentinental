"""
Unit tests for CAN Attack Simulation Suite.
Phase 2, Day 6 Verification
"""

import unittest
from src.sim.bus_emulator import VirtualCANBus, CANFrame
from src.attacks.attack_suite import CANAttackSuite
from src.sim.ecu_generator import CAN_ID_BRAKE_OVERRIDE, CAN_ID_ENGINE_RPM

class TestCANAttackSuite(unittest.TestCase):
    """Verify attack frame crafting, burst injection, and high-frequency flood patterns."""

    def setUp(self):
        self.bus = VirtualCANBus()

    def test_craft_flood_frame(self):
        frame = CANAttackSuite.craft_flood_frame(target_id=0x000)
        self.assertEqual(frame.can_id, 0x000)
        self.assertEqual(frame.dlc, 8)
        self.assertEqual(frame.data, b'\x00' * 8)

    def test_craft_spoof_brake_frame(self):
        frame = CANAttackSuite.craft_spoof_brake_frame(brake_pct=100, abs_active=True)
        self.assertEqual(frame.can_id, CAN_ID_BRAKE_OVERRIDE)
        self.assertEqual(frame.dlc, 6)
        self.assertEqual(frame.data[0], 100) # 100% Brake Pressure
        self.assertEqual(frame.data[1], 1)   # ABS Active

    def test_craft_spoof_engine_kill_frame(self):
        frame = CANAttackSuite.craft_spoof_engine_kill_frame()
        self.assertEqual(frame.can_id, CAN_ID_ENGINE_RPM)
        self.assertEqual(frame.dlc, 4)
        self.assertEqual(frame.data[0], 0)
        self.assertEqual(frame.data[1], 0)

    def test_craft_fuzzing_frame(self):
        frame = CANAttackSuite.craft_fuzzing_frame()
        self.assertGreaterEqual(frame.can_id, 0x001)
        self.assertLessEqual(frame.can_id, 0x7FE)
        self.assertGreaterEqual(frame.dlc, 1)
        self.assertLessEqual(frame.dlc, 8)
        self.assertEqual(len(frame.data), frame.dlc)

    def test_dos_flood_injection(self):
        sub_queue = self.bus.create_subscriber()
        injected = CANAttackSuite.inject_dos_flood(self.bus, count=50, rate_hz=5000.0)

        self.assertEqual(len(injected), 50)
        self.assertEqual(sub_queue.qsize(), 50)
        self.bus.remove_subscriber(sub_queue)

if __name__ == "__main__":
    unittest.main()
