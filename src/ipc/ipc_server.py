"""
High-Speed IPC Server for CAN-Sentinel.
Phase 3, Day 12: Inter-Process Communication (IPC) Bridge

Hosts a Unix Domain Socket server (/tmp/can_sentinel.sock) with automatic TCP fallback,
unpacking raw 24-byte binary C frame structs and dispatching to Python AI detection engines.
"""

import os
import sys
import time
import struct
import socket
import select
import threading
from typing import Callable, List, Optional
from ..sim.bus_emulator import CANFrame

# Binary format matching can_sentinel_ipc_frame_t in can_sentinel_common.h:
# uint64_t timestamp_us (8)
# uint32_t can_id       (4)
# uint8_t  dlc          (1)
# uint8_t  data[8]      (8)
# uint8_t  is_extended  (1)
# uint8_t  is_error     (1)
# uint8_t  is_rtr       (1)
# Total: 24 bytes packed (=QIB8sBBB)
IPC_FRAME_STRUCT_FORMAT = "=QIB8sBBB"
IPC_FRAME_SIZE = struct.calcsize(IPC_FRAME_STRUCT_FORMAT)

DEFAULT_UNIX_SOCKET_PATH = "/tmp/can_sentinel.sock"
DEFAULT_TCP_PORT = 5555

class CANIPCServer:
    """
    Multithreaded IPC server receiving binary CAN frame packets from C sniffer/bridge.
    """

    def __init__(
        self,
        unix_socket_path: str = DEFAULT_UNIX_SOCKET_PATH,
        tcp_port: int = DEFAULT_TCP_PORT,
        use_tcp: Optional[bool] = None
    ):
        self.unix_socket_path = unix_socket_path
        self.tcp_port = tcp_port
        # Default to TCP on non-Linux systems, Unix sockets on Linux
        if use_tcp is None:
            self.use_tcp = (os.name != "posix" or not hasattr(socket, "AF_UNIX"))
        else:
            self.use_tcp = use_tcp

        self.running = False
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[CANFrame], None]] = []
        self.total_frames_received = 0

    def add_frame_subscriber(self, callback: Callable[[CANFrame], None]) -> None:
        """Register a subscriber callback invoked for every unpacked frame."""
        self._callbacks.append(callback)

    def _dispatch_frame(self, frame: CANFrame) -> None:
        """Forward frame to all registered detection/UI subscribers."""
        self.total_frames_received += 1
        for cb in self._callbacks:
            try:
                cb(frame)
            except Exception as e:
                print(f"[!] Warning in IPC subscriber callback: {e}")

    @staticmethod
    def unpack_binary_frame(raw_bytes: bytes) -> CANFrame:
        """Unpack 24-byte binary payload into a CANFrame instance."""
        if len(raw_bytes) != IPC_FRAME_SIZE:
            raise ValueError(f"Invalid frame size: {len(raw_bytes)} != {IPC_FRAME_SIZE}")

        ts_us, can_id, dlc, data_bytes, is_ext, is_err, is_rtr = struct.unpack(
            IPC_FRAME_STRUCT_FORMAT, raw_bytes
        )

        timestamp_sec = float(ts_us) / 1000000.0 if ts_us > 0 else time.time()
        actual_data = data_bytes[:dlc]

        return CANFrame(
            can_id=can_id,
            data=actual_data,
            dlc=dlc,
            is_extended=bool(is_ext),
            is_error=bool(is_err),
            is_rtr=bool(is_rtr),
            timestamp=timestamp_sec
        )

    def _handle_client(self, client_sock: socket.socket) -> None:
        """Read and process streaming frame structs from a connected C client."""
        buffer = bytearray()
        try:
            while self.running:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                while len(buffer) >= IPC_FRAME_SIZE:
                    frame_bytes = bytes(buffer[:IPC_FRAME_SIZE])
                    del buffer[:IPC_FRAME_SIZE]
                    frame = self.unpack_binary_frame(frame_bytes)
                    self._dispatch_frame(frame)
        except Exception:
            pass
        finally:
            client_sock.close()

    def _server_loop(self) -> None:
        """Main server listening loop."""
        if self.use_tcp:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("127.0.0.1", self.tcp_port))
            self._server_sock.listen(5)
            self._server_sock.settimeout(1.0)
            print(f"[+] IPC Server listening on TCP 127.0.0.1:{self.tcp_port}")
        else:
            if os.path.exists(self.unix_socket_path):
                os.remove(self.unix_socket_path)
            self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._server_sock.bind(self.unix_socket_path)
            self._server_sock.listen(5)
            self._server_sock.settimeout(1.0)
            print(f"[+] IPC Server listening on Unix Domain Socket: {self.unix_socket_path}")

        while self.running:
            try:
                client_sock, _ = self._server_sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock,),
                    daemon=True
                )
                client_thread.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def start(self) -> None:
        """Start the IPC server in a background thread."""
        if self.running: return
        self.running = True
        self._thread = threading.Thread(target=self._server_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the IPC server and clean up socket files."""
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if not self.use_tcp and os.path.exists(self.unix_socket_path):
            try:
                os.remove(self.unix_socket_path)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)
