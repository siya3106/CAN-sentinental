"""
Multi-ECU Telemetry Simulator (Python Engine).
Phase 1, Day 3: Multi-ECU Telemetry Simulation

Simulates concurrent vehicle ECUs with realistic automotive physics,
inter-arrival delta times (Δt), and binary CAN payload byte encoding.
"""

import time
import math
import struct
import threading
from typing import List, Callable, Optional, Dict, Any
from .bus_emulator import CANFrame, VirtualCANBus

# Standard ECU Arbitration IDs
CAN_ID_BRAKE_OVERRIDE   = 0x0A0  # 10ms (100 Hz)
CAN_ID_ENGINE_RPM       = 0x110  # 20ms (50 Hz)
CAN_ID_VEHICLE_SPEED    = 0x120  # 50ms (20 Hz)
CAN_ID_ENGINE_TEMP      = 0x130  # 100ms (10 Hz)
CAN_ID_TRANSMISSION     = 0x180  # 50ms (20 Hz)
CAN_ID_BODY_DOORS       = 0x230  # 100ms (10 Hz)
CAN_ID_BODY_CLIMATE     = 0x240  # 200ms (5 Hz)
CAN_ID_LIGHTING         = 0x270  # 100ms (10 Hz)

class VehicleECUSimulator:
    """
    Simulates a multi-node automotive CAN bus with Engine, Transmission,
    Braking/ABS, and Body ECUs running concurrently.
    """

    def __init__(self, bus: Optional[VirtualCANBus] = None):
        self.bus = bus if bus is not None else VirtualCANBus()
        self.running = False
        self._threads: List[threading.Thread] = []
        self._callbacks: List[Callable[[CANFrame], None]] = []

        # Vehicle physical state
        self.speed_kmh = 0.0
        self.rpm = 800.0
        self.engine_temp_c = 45.0
        self.throttle_pct = 0.0
        self.brake_pct = 0.0
        self.gear = 0
        self.doors_locked = 1
        self.headlights = 1
        self.steering_angle = 0.0
        self._state_lock = threading.Lock()

    def add_frame_callback(self, callback: Callable[[CANFrame], None]) -> None:
        """Register a subscriber callback for each generated CAN frame."""
        self._callbacks.append(callback)

    def _broadcast(self, frame: CANFrame) -> None:
        """Dispatch frame to the bus and any registered callbacks."""
        self.bus.send(frame)
        for cb in self._callbacks:
            try:
                cb(frame)
            except Exception:
                pass

    def _physics_loop(self) -> None:
        """Simulate vehicle dynamics (acceleration, cruising, braking cycle)."""
        time_sec = 0.0
        while self.running:
            with self._state_lock:
                cycle_t = time_sec % 60.0

                if cycle_t < 15.0:
                    # Accelerating
                    progress = cycle_t / 15.0
                    self.throttle_pct = 40.0 + 20.0 * math.sin(progress * math.pi)
                    self.brake_pct = 0.0
                    self.speed_kmh = progress * 75.0
                    if self.speed_kmh < 15: self.gear = 1
                    elif self.speed_kmh < 35: self.gear = 2
                    elif self.speed_kmh < 55: self.gear = 3
                    else: self.gear = 4
                    self.rpm = 1200.0 + (self.throttle_pct * 45.0) + (self.speed_kmh * 20.0)
                elif cycle_t < 35.0:
                    # Cruising
                    self.throttle_pct = 20.0 + 5.0 * math.sin(cycle_t)
                    self.brake_pct = 0.0
                    self.speed_kmh = 75.0 + 3.0 * math.sin(cycle_t * 0.5)
                    self.gear = 4
                    self.rpm = 2100.0 + 100.0 * math.sin(cycle_t)
                elif cycle_t < 48.0:
                    # Decelerating / Braking
                    brake_t = (cycle_t - 35.0) / 13.0
                    self.throttle_pct = 0.0
                    self.brake_pct = 35.0 + 15.0 * math.sin(brake_t * math.pi)
                    self.speed_kmh = max(0.0, 75.0 * (1.0 - brake_t))
                    self.rpm = max(800.0, 2100.0 * (1.0 - brake_t))
                    if self.speed_kmh < 10: self.gear = 1
                    elif self.speed_kmh < 30: self.gear = 2
                else:
                    # Idling at stop
                    self.throttle_pct = 0.0
                    self.brake_pct = 50.0
                    self.speed_kmh = 0.0
                    self.gear = 0
                    self.rpm = 790.0 + 15.0 * math.sin(cycle_t)

                if self.engine_temp_c < 90.0:
                    self.engine_temp_c += 0.05

            time_sec += 0.05
            time.sleep(0.05)

    def _engine_ecu_loop(self) -> None:
        """Engine ECU: 0x110 RPM @ 20ms, 0x120 Speed @ 50ms, 0x130 Temp @ 100ms."""
        tick = 0
        while self.running:
            with self._state_lock:
                rpm_val = int(self.rpm)
                throttle_val = int(self.throttle_pct)
                speed_raw = int(self.speed_kmh * 100)
                temp_val = int(self.engine_temp_c)

            now = time.time()

            # 1. Engine RPM (0x110, 20ms)
            rpm_data = struct.pack(">HBB", rpm_val, throttle_val, 0x01)
            self._broadcast(CANFrame(CAN_ID_ENGINE_RPM, rpm_data, dlc=4, timestamp=now))

            # 2. Vehicle Speed (0x120, ~50ms)
            if tick % 2 == 0:
                speed_data = struct.pack(">HBB", speed_raw, 0x00, 0x4A)
                self._broadcast(CANFrame(CAN_ID_VEHICLE_SPEED, speed_data, dlc=4, timestamp=now))

            # 3. Engine Temp (0x130, ~100ms)
            if tick % 5 == 0:
                temp_data = struct.pack("BBB", temp_val + 40, 0x42, 0x00)
                self._broadcast(CANFrame(CAN_ID_ENGINE_TEMP, temp_data, dlc=3, timestamp=now))

            tick += 1
            time.sleep(0.02)

    def _transmission_ecu_loop(self) -> None:
        """Transmission ECU: 0x180 Gear & Torque @ 50ms."""
        while self.running:
            with self._state_lock:
                gear_val = self.gear
                torque_nm = int(self.throttle_pct * 3.5)

            trans_data = struct.pack(">BHBB", gear_val, torque_nm, 1 if gear_val > 0 else 0, 0x00)
            self._broadcast(CANFrame(CAN_ID_TRANSMISSION, trans_data, dlc=5, timestamp=time.time()))
            time.sleep(0.05)

    def _brake_ecu_loop(self) -> None:
        """Brake / ABS ECU: 0x0A0 Brake Pressure & Wheel Speeds @ 10ms."""
        while self.running:
            with self._state_lock:
                brake_val = int(self.brake_pct)
                speed_base = int(self.speed_kmh)
                abs_active = 1 if (brake_val > 70 and speed_base > 40) else 0

            wheel_rl = max(0, speed_base - 1)
            brake_data = struct.pack("BBBBBB", brake_val, abs_active, speed_base, speed_base, wheel_rl, wheel_rl)
            self._broadcast(CANFrame(CAN_ID_BRAKE_OVERRIDE, brake_data, dlc=6, timestamp=time.time()))
            time.sleep(0.01)

    def _body_ecu_loop(self) -> None:
        """Body & Climate ECU: 0x230 Doors @ 100ms, 0x240 Climate @ 200ms."""
        tick = 0
        while self.running:
            with self._state_lock:
                doors = self.doors_locked
                lights = self.headlights

            now = time.time()
            # 1. Body Doors
            door_data = struct.pack("BBBB", 0xFF if doors else 0x00, 0x00, 0x01, 0x00)
            self._broadcast(CANFrame(CAN_ID_BODY_DOORS, door_data, dlc=4, timestamp=now))

            # 2. Climate (200ms)
            if tick % 2 == 0:
                climate_data = struct.pack("BBBB", 22, 21, 0x03, 0x01)
                self._broadcast(CANFrame(CAN_ID_BODY_CLIMATE, climate_data, dlc=4, timestamp=now))

            # 3. Lighting (100ms)
            light_data = struct.pack("BB", 0x01 if lights else 0x00, 0x00)
            self._broadcast(CANFrame(CAN_ID_LIGHTING, light_data, dlc=2, timestamp=now))

            tick += 1
            time.sleep(0.1)

    def start(self) -> None:
        """Start all ECU simulation threads."""
        if self.running: return
        self.running = True

        self._threads = [
            threading.Thread(target=self._physics_loop, name="PhysicsEngine", daemon=True),
            threading.Thread(target=self._engine_ecu_loop, name="EngineECU", daemon=True),
            threading.Thread(target=self._transmission_ecu_loop, name="TransECU", daemon=True),
            threading.Thread(target=self._brake_ecu_loop, name="BrakeECU", daemon=True),
            threading.Thread(target=self._body_ecu_loop, name="BodyECU", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        """Gracefully stop all ECU threads."""
        self.running = False
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

    def generate_batch(self, duration_sec: float = 10.0) -> List[CANFrame]:
        """
        Deterministically generate a chronological list of normal CAN frames
        over the specified duration for baseline dataset generation and tests.
        """
        frames: List[CANFrame] = []
        dt = 0.005 # 5ms simulation resolution
        total_steps = int(duration_sec / dt)
        sim_time = 1000000.0 # Base timestamp

        rpm = 800.0
        speed = 0.0
        gear = 0
        temp = 45.0
        throttle = 0.0
        brake = 0.0

        for step in range(total_steps):
            t = step * dt
            current_time = sim_time + t

            # Physics state
            cycle_t = t % 60.0
            if cycle_t < 15.0:
                p = cycle_t / 15.0
                throttle = 40.0 + 20.0 * math.sin(p * math.pi)
                brake = 0.0
                speed = p * 75.0
                gear = 1 if speed < 15 else (2 if speed < 35 else (3 if speed < 55 else 4))
                rpm = 1200.0 + (throttle * 45.0) + (speed * 20.0)
            elif cycle_t < 35.0:
                throttle = 20.0 + 5.0 * math.sin(cycle_t)
                brake = 0.0
                speed = 75.0 + 3.0 * math.sin(cycle_t * 0.5)
                gear = 4
                rpm = 2100.0 + 100.0 * math.sin(cycle_t)
            elif cycle_t < 48.0:
                bt = (cycle_t - 35.0) / 13.0
                throttle = 0.0
                brake = 35.0 + 15.0 * math.sin(bt * math.pi)
                speed = max(0.0, 75.0 * (1.0 - bt))
                rpm = max(800.0, 2100.0 * (1.0 - bt))
                gear = 1 if speed < 10 else (2 if speed < 30 else 3)
            else:
                throttle = 0.0
                brake = 50.0
                speed = 0.0
                gear = 0
                rpm = 790.0 + 15.0 * math.sin(cycle_t)

            if temp < 90.0:
                temp += 0.005

            # 1. Brake ECU @ 10ms (every 2 steps)
            if step % 2 == 0:
                abs_act = 1 if (brake > 70 and speed > 40) else 0
                b_data = struct.pack("BBBBBB", int(brake), abs_act, int(speed), int(speed), max(0, int(speed)-1), max(0, int(speed)-1))
                frames.append(CANFrame(CAN_ID_BRAKE_OVERRIDE, b_data, dlc=6, timestamp=current_time))

            # 2. Engine RPM @ 20ms (every 4 steps)
            if step % 4 == 0:
                rpm_data = struct.pack(">HBB", int(rpm), int(throttle), 0x01)
                frames.append(CANFrame(CAN_ID_ENGINE_RPM, rpm_data, dlc=4, timestamp=current_time))

            # 3. Vehicle Speed @ 50ms (every 10 steps)
            if step % 10 == 0:
                speed_data = struct.pack(">HBB", int(speed * 100), 0x00, 0x4A)
                frames.append(CANFrame(CAN_ID_VEHICLE_SPEED, speed_data, dlc=4, timestamp=current_time))

            # 4. Transmission @ 50ms (every 10 steps)
            if step % 10 == 0:
                trans_data = struct.pack(">BHBB", gear, int(throttle * 3.5), 1 if gear > 0 else 0, 0x00)
                frames.append(CANFrame(CAN_ID_TRANSMISSION, trans_data, dlc=5, timestamp=current_time))

            # 5. Engine Temp @ 100ms (every 20 steps)
            if step % 20 == 0:
                temp_data = struct.pack("BBB", int(temp) + 40, 0x42, 0x00)
                frames.append(CANFrame(CAN_ID_ENGINE_TEMP, temp_data, dlc=3, timestamp=current_time))

            # 6. Body Doors @ 100ms (every 20 steps)
            if step % 20 == 0:
                door_data = struct.pack("BBBB", 0xFF, 0x00, 0x01, 0x00)
                frames.append(CANFrame(CAN_ID_BODY_DOORS, door_data, dlc=4, timestamp=current_time))

            # 7. Lighting @ 100ms (every 20 steps)
            if step % 20 == 0:
                light_data = struct.pack("BB", 0x01, 0x00)
                frames.append(CANFrame(CAN_ID_LIGHTING, light_data, dlc=2, timestamp=current_time))

            # 8. Climate @ 200ms (every 40 steps)
            if step % 40 == 0:
                climate_data = struct.pack("BBBB", 22, 21, 0x03, 0x01)
                frames.append(CANFrame(CAN_ID_BODY_CLIMATE, climate_data, dlc=4, timestamp=current_time))

        return frames
