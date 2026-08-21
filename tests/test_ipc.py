"""
Unit tests for IPC Streaming, Real-Time Detection, and Alert Engine.
Phase 3 Verification
"""

import os
import time
import struct
import socket
import unittest
import tempfile
from src.sim.bus_emulator import CANFrame
from src.ipc.ipc_server import CANIPCServer, IPC_FRAME_SIZE, IPC_FRAME_STRUCT_FORMAT
from src.detection.stream_detector import StreamAnomalyDetector
from src.detection.alert_engine import AlertEngine

class TestIPCandDetectionPipeline(unittest.TestCase):
    """Verify binary IPC frame packing, socket dispatch, real-time detection, and heuristic alerting."""

    def test_binary_frame_unpacking(self):
        # Pack a 24-byte binary C struct
        # uint64 ts_us = 1000000000 (1000.0s)
        # uint32 can_id = 0x110
        # uint8 dlc = 4
        # uint8 data[8] = 0x09, 0xC4, 0x28, 0x01, 0, 0, 0, 0
        # uint8 is_ext = 0, is_err = 0, is_rtr = 0
        raw_pkt = struct.pack(
            IPC_FRAME_STRUCT_FORMAT,
            1000000000,
            0x110,
            4,
            b'\x09\xC4\x28\x01\x00\x00\x00\x00',
            0,
            0,
            0
        )
        self.assertEqual(len(raw_pkt), IPC_FRAME_SIZE)

        frame = CANIPCServer.unpack_binary_frame(raw_pkt)
        self.assertEqual(frame.can_id, 0x110)
        self.assertEqual(frame.dlc, 4)
        self.assertEqual(frame.data, b'\x09\xC4\x28\x01')
        self.assertAlmostEqual(frame.timestamp, 1000.0, places=3)
        self.assertFalse(frame.is_extended)

    def test_ipc_server_tcp_dispatch(self):
        received_frames = []
        server = CANIPCServer(tcp_port=5599, use_tcp=True)
        server.add_frame_subscriber(lambda f: received_frames.append(f))
        server.start()
        time.sleep(0.1)

        # Connect client and send a frame
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", 5599))
            raw_pkt = struct.pack(
                IPC_FRAME_STRUCT_FORMAT,
                2000000000,
                0x0A0,
                6,
                b'\x64\x01\x00\x00\x00\x00\x00\x00',
                0,
                0,
                0
            )
            client.sendall(raw_pkt)
            client.close()

            # Wait for reception
            time.sleep(0.15)
            self.assertEqual(len(received_frames), 1)
            self.assertEqual(received_frames[0].can_id, 0x0A0)
        finally:
            server.stop()

    def test_detection_and_alert_engine(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            alert_log_path = tmp.name

        try:
            detector = StreamAnomalyDetector(sliding_window_size=20)
            alert_engine = AlertEngine(log_filepath=alert_log_path)
            alerts_received = []
            alert_engine.add_alert_callback(lambda a: alerts_received.append(a))

            # Send a burst of DoS flood frames (0x000)
            for i in range(30):
                f = CANFrame(0x000, b'\x00' * 8, dlc=8, timestamp=1000.0 + (i * 0.0002))
                det = detector.process_frame(f)
                alert_engine.evaluate_detection(det)

            self.assertGreater(alert_engine.alert_counter, 0)
            self.assertGreater(len(alerts_received), 0)
            # Verify alert classification
            first_alert = alerts_received[0]
            self.assertEqual(first_alert.can_id, 0x000)
            self.assertEqual(first_alert.attack_type, "DOS_BUS_FLOOD")
            self.assertEqual(first_alert.severity, "CRITICAL")
        finally:
            if os.path.exists(alert_log_path):
                os.remove(alert_log_path)

if __name__ == "__main__":
    unittest.main()
