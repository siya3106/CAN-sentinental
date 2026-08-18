# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![Status](https://img.shields.io/badge/Phase%201-Completed-success.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and forensic diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters and multi-threaded ECU simulators, high-speed telemetry frame parsing with microsecond inter-arrival delta time ($\Delta t$) tracking, Shannon entropy estimation, and forensic CSV telemetry data logging.

---

## Phase 1 Architecture & Core Deliverables

- **Virtual Interface & Environment Configuration**: Automated Linux `vcan0` setup and teardown management (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`).
- **Low-Level C SocketCAN Broadcaster**: `src/c/can_broadcaster.c` implementing Linux SocketCAN `PF_CAN`, `SOCK_RAW`, and `struct can_frame` with frequency-controlled bursts.
- **Multi-Threaded C Multi-ECU Simulation**: `src/c/ecu_sim.c` with POSIX threads broadcasting realistic powertrain, chassis, brake, and body ECU telemetry.
- **Cross-Platform Bus Emulation & ECU Generator**: `src/sim/bus_emulator.py` and `src/sim/ecu_generator.py` providing in-memory virtual CAN broadcasting.
- **SocketCAN Telemetry Parser & Signal Decoder**: `src/parser/telemetry_parser.py` parsing raw frames, decoding vehicle DBC signals, and computing per-ID delta times ($\Delta t$) and Shannon entropy.
- **Forensic CSV Telemetry Data Logger**: `src/logger/csv_logger.py` streaming parsed telemetry to `dataset/normal_traffic.csv` for baseline modeling.

---

## Repository Structure

```
can-sentinel/
├── Makefile                       # Build automation for C tools & test runners
├── requirements.txt               # Python package dependencies
├── scripts/
│   ├── setup_vcan.sh              # Linux vcan0 initialization script
│   └── teardown_vcan.sh           # vcan0 teardown & cleanup script
├── src/
│   ├── c/
│   │   ├── can_sentinel_common.h  # Common arbitration IDs, structs & formatting macros
│   │   ├── can_broadcaster.c      # Low-level C SocketCAN broadcaster & frame crafter
│   │   └── ecu_sim.c              # Multi-threaded C multi-ECU telemetry simulator
│   ├── sim/
│   │   ├── bus_emulator.py        # Virtual bus abstraction & socketcan fallback
│   │   └── ecu_generator.py       # Python multi-ECU physics and telemetry simulator
│   ├── parser/
│   │   └── telemetry_parser.py    # Frame parser, signal decoder & delta-t extractor
│   ├── logger/
│   │   └── csv_logger.py          # Forensic CSV telemetry data logger
│   ├── attacks/                   # Attack engines
│   ├── ml/                        # ML anomaly detection pipelines
│   ├── ipc/                       # Socket IPC streaming bridges
│   ├── detection/                 # Real-time streaming detector
│   ├── defense/                   # Active error-frame mitigation
│   └── ui/                        # Diagnostic dashboard & vehicle topology
├── dataset/
│   └── normal_traffic.csv         # Baseline normal vehicle telemetry dataset
├── models/                        # Serialized ML models & metadata
├── logs/                          # Forensic alert logs
└── tests/
    ├── test_broadcaster.py        # Frame packing and arbitration tests
    ├── test_sim.py                # Multi-ECU simulation & timing tests
    ├── test_parser.py             # Telemetry parser & entropy tests
    └── test_logger.py             # CSV logger & schema tests
```

---

## Automotive ECU Arbitration IDs & Signals

| Subsystem | CAN ID | Period ($\Delta t$) | Frequency | Signals Encoded |
| :--- | :--- | :--- | :--- | :--- |
| **Brake / ABS** | `0x0A0` | **10 ms** | 100 Hz | Brake pedal pressure %, ABS active bit, Wheel speeds FL/FR/RL/RR |
| **Engine Powertrain** | `0x110` | **20 ms** | 50 Hz | Engine RPM (16-bit), Throttle %, Engine Status |
| **Vehicle Dynamics** | `0x120` | **50 ms** | 20 Hz | Vehicle Speed km/h (scale: 0.01), Odometer |
| **Coolant & Oil** | `0x130` | **100 ms** | 10 Hz | Engine Coolant Temp °C (offset +40), Oil Pressure bar |
| **Transmission** | `0x180` | **50 ms** | 20 Hz | Current Gear (1..6), Clutch state, Torque demand Nm |
| **Body ECU (Doors)** | `0x230` | **100 ms** | 10 Hz | 4-door lock status, Driver seatbelt, Window state |
| **Climate / HVAC** | `0x240` | **200 ms** | 5 Hz | Target Cabin Temp °C, Ambient Temp °C, Fan Speed, AC bit |
| **Lighting** | `0x270` | **100 ms** | 10 Hz | Headlights / Low beam, Turn signals |

---

## Getting Started & Usage Guide

### 1. Initialize Virtual CAN (`vcan0`)
On a Linux host with `can-utils`:
```bash
sudo bash scripts/setup_vcan.sh
```

### 2. Build and Run C Multi-ECU Telemetry Simulation
```bash
make bin/ecu_sim
./bin/ecu_sim -i vcan0 -m normal
```

### 3. Log Telemetry to CSV Dataset
Stream live frames or generate baseline datasets:
```bash
python -m src.logger.csv_logger --output dataset/normal_traffic.csv --duration 30
```

### 4. Run Automated Test Suite
```bash
pytest tests/ -v
```
