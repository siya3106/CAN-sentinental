"""
CAN Bus Emulator and Hardware/Virtual Interface Abstraction.
Phase 1: Environment & Virtual Interface Support
"""

import time
import queue
import threading
from typing import Optional, Dict, Any, List

class CANFrame:
    """Represents a standard or extended CAN frame."""
    def __init__(
        self,
        can_id: int,
        data: bytes,
        dlc: Optional[int] = None,
        is_extended: bool = False,
        is_error: bool = False,
        is_rtr: bool = False,
        timestamp: Optional[float] = None
    ):
        self.can_id = can_id
        self.data = bytes(data)
        self.dlc = len(self.data) if dlc is None else min(dlc, 8)
        self.is_extended = is_extended
        self.is_error = is_error
        self.is_rtr = is_rtr
        self.timestamp = timestamp if timestamp is not None else time.time()

    def __repr__(self) -> str:
        data_hex = " ".join(f"{b:02X}" for b in self.data[:self.dlc])
        flags = []
        if self.is_extended: flags.append("EXT")
        if self.is_error: flags.append("ERR")
        if self.is_rtr: flags.append("RTR")
        flag_str = f" [{','.join(flags)}]" if flags else ""
        return f"<CANFrame ID=0x{self.can_id:03X}{flag_str} DLC={self.dlc} Data=[{data_hex}] @ {self.timestamp:.6f}>"


class VirtualCANBus:
    """Thread-safe virtual in-memory CAN bus for cross-platform simulation and testing."""
    _instance = None
    _lock = threading.Lock()

    def __init__(self, channel: str = "vcan0"):
        self.channel = channel
        self._subscribers: List[queue.Queue] = []
        self._is_open = True
        self._bus_lock = threading.Lock()

    def send(self, frame: CANFrame) -> None:
        """Broadcast a CAN frame to all connected virtual bus listeners."""
        if not self._is_open:
            raise RuntimeError("Cannot send frame on closed Virtual CAN Bus.")

        with self._bus_lock:
            # Deliver a copy of the frame to all subscriber queues
            for q in self._subscribers:
                try:
                    q.put_nowait(frame)
                except queue.Full:
                    pass # Drop frame if subscriber buffer is exhausted

    def create_subscriber(self, maxsize: int = 10000) -> queue.Queue:
        """Create a dedicated FIFO queue for sniffing bus frames."""
        q = queue.Queue(maxsize=maxsize)
        with self._bus_lock:
            self._subscribers.append(q)
        return q

    def remove_subscriber(self, q: queue.Queue) -> None:
        """Unregister a subscriber queue."""
        with self._bus_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def close(self) -> None:
        """Close the virtual bus."""
        with self._bus_lock:
            self._is_open = False
            self._subscribers.clear()


def create_can_bus(channel: str = "vcan0", interface: str = "auto") -> Any:
    """
    Factory function returning a Linux SocketCAN bus if available,
    or a thread-safe VirtualCANBus instance for local cross-platform development.
    """
    if interface == "socketcan" or (interface == "auto" and hasattr(time, "CLOCK_REALTIME")):
        try:
            import can # python-can
            bus = can.interface.Bus(channel=channel, bustype="socketcan")
            return bus
        except Exception:
            pass

    # Default to cross-platform VirtualCANBus
    return VirtualCANBus(channel=channel)
