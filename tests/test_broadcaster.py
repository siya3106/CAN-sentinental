"""
Unit tests for CAN frame crafting and telemetry structure logic.
Phase 1, Day 2 Verification
"""

import unittest
import struct

class TestCANFrameCrafting(unittest.TestCase):
    """Test standard and extended CAN frame packing and arbitration IDs."""

    CAN_EFF_FLAG = 0x80000000
    CAN_RTR_FLAG = 0x40000000
    CAN_ERR_FLAG = 0x20000000
    CAN_SFF_MASK = 0x000007FF
    CAN_EFF_MASK = 0x1FFFFFFF

    # Automotive ECU ID constants
    CAN_ID_BRAKE_OVERRIDE = 0x0A0
    CAN_ID_ENGINE_RPM = 0x110
    CAN_ID_VEHICLE_SPEED = 0x120
    CAN_ID_BODY_DOORS = 0x230

    def craft_can_frame(self, can_id: int, dlc: int, data: bytes, is_extended: bool = False) -> bytes:
        """Emulate Linux SocketCAN struct can_frame layout in Python.
        struct can_frame {
            canid_t can_id;  // 4 bytes (uint32)
            uint8_t can_dlc; // 1 byte
            uint8_t __pad;   // 1 byte
            uint8_t __res0;  // 1 byte
            uint8_t __res1;  // 1 byte
            uint8_t data[8]; // 8 bytes
        }; // Total 16 bytes
        """
        if is_extended:
            packed_id = (can_id & self.CAN_EFF_MASK) | self.CAN_EFF_FLAG
        else:
            packed_id = can_id & self.CAN_SFF_MASK

        dlc = min(dlc, 8)
        padded_data = data.ljust(8, b'\x00')
        return struct.pack("=IBBB8s", packed_id, dlc, 0, 0, 0, padded_data)

    def test_standard_engine_rpm_frame(self):
        rpm = 2500
        payload = struct.pack(">HBB", rpm, 0x01, 0x00) # Big-endian 16-bit RPM + status
        frame_bytes = self.craft_can_frame(self.CAN_ID_ENGINE_RPM, 4, payload)

        self.assertEqual(len(frame_bytes), 16)
        can_id, dlc, _, _, _, data = struct.unpack("=IBBB8s", frame_bytes)
        self.assertEqual(can_id, 0x110)
        self.assertEqual(dlc, 4)
        self.assertEqual(data[:4], payload)

    def test_extended_id_frame(self):
        ext_id = 0x18DAF110
        payload = b'\x02\x01\x0C\x00\x00\x00\x00\x00'
        frame_bytes = self.craft_can_frame(ext_id, 8, payload, is_extended=True)

        can_id, dlc, _, _, _, data = struct.unpack("=IBBB8s", frame_bytes)
        self.assertTrue(can_id & self.CAN_EFF_FLAG)
        self.assertEqual(can_id & self.CAN_EFF_MASK, ext_id)
        self.assertEqual(dlc, 8)
        self.assertEqual(data, payload)

    def test_hex_payload_parsing(self):
        hex_input = "DEADBEEFCAFE0102"
        raw_bytes = bytes.fromhex(hex_input)
        self.assertEqual(len(raw_bytes), 8)
        self.assertEqual(raw_bytes[0], 0xDE)
        self.assertEqual(raw_bytes[1], 0xAD)
        self.assertEqual(raw_bytes[3], 0xEF)

if __name__ == "__main__":
    unittest.main()
