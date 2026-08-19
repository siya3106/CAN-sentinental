# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![Status](https://img.shields.io/badge/Phase%202-Day%206%20Complete-blue.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and forensic diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters and multi-threaded ECU simulators, high-speed telemetry frame parsing with microsecond inter-arrival delta time ($\Delta t$) tracking, Shannon entropy estimation, forensic CSV telemetry data logging, and comprehensive malware/attack injection suites.

---

## Core Architecture & Implemented Deliverables

- **Virtual Interface & Environment Configuration**: Automated Linux `vcan0` setup and teardown management (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`).
- **Low-Level C SocketCAN Broadcaster**: `src/c/can_broadcaster.c` implementing Linux SocketCAN `PF_CAN`, `SOCK_RAW`, and `struct can_frame` with frequency-controlled bursts.
- **Multi-Threaded C Multi-ECU Simulation**: `src/c/ecu_sim.c` with POSIX threads broadcasting realistic powertrain, chassis, brake, and body ECU telemetry.
- **Cross-Platform Bus Emulation & ECU Generator**: `src/sim/bus_emulator.py` and `src/sim/ecu_generator.py` providing in-memory virtual CAN broadcasting.
- **SocketCAN Telemetry Parser & Signal Decoder**: `src/parser/telemetry_parser.py` parsing raw frames, decoding vehicle DBC signals, and computing per-ID delta times ($\Delta t$) and Shannon entropy.
- **Forensic CSV Telemetry Data Logger**: `src/logger/csv_logger.py` streaming parsed telemetry to `dataset/normal_traffic.csv` for baseline modeling.
- **Malware & Attack Injection Suite**: `src/c/attack_injector.c` and `src/attacks/attack_suite.py` simulating high-frequency DoS flooding, Brake/Engine spoofing, randomized payload fuzzing, and replay attacks.

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
│   │   ├── ecu_sim.c              # Multi-threaded C multi-ECU telemetry simulator
│   │   └── attack_injector.c      # Low-level C SocketCAN attack & malware injector
│   ├── sim/
│   │   ├── bus_emulator.py        # Virtual bus abstraction & socketcan fallback
│   │   └── ecu_generator.py       # Python multi-ECU physics and telemetry simulator
│   ├── parser/
│   │   └── telemetry_parser.py    # Frame parser, signal decoder & delta-t extractor
│   ├── logger/
│   │   └── csv_logger.py          # Forensic CSV telemetry data logger
│   ├── attacks/
│   │   └── attack_suite.py        # Python attack injection & dataset generation suite
│   ├── ml/                        # ML anomaly detection pipelines
│   ├── ipc/                       # Socket IPC streaming bridges
│   ├── detection/                 # Real-time streaming detector
│   ├── defense/                   # Active error-frame mitigation
│   └── ui/                        # Diagnostic dashboard & vehicle topology
├── dataset/
│   ├── normal_traffic.csv         # Baseline normal vehicle telemetry dataset
│   └── attack_traffic.csv         # Labeled attack injection evaluation dataset
├── models/                        # Serialized ML models & metadata
├── logs/                          # Forensic alert logs
└── tests/
    ├── test_broadcaster.py        # Frame packing and arbitration tests
    ├── test_sim.py                # Multi-ECU simulation & timing tests
    ├── test_parser.py             # Telemetry parser & entropy tests
    ├── test_logger.py             # CSV logger & schema tests
    └── test_attack.py             # Attack simulation & burst tests
```

---

## Attack Vectors & Injection Profiles

| Attack Vector | Mode Flag | Target CAN ID | Typical Rate | Impact on Vehicle Bus |
| :--- | :--- | :--- | :--- | :--- |
| **DoS Bus Flood** | `flood` | `0x000` (Dominant) | 2,500+ fps | Starves bus arbitration, delaying critical safety packets |
| **Brake Override Spoof** | `spoof-brake`| `0x0A0` (Brake ECU) | 150 fps | Forces 100% false brake pressure and ABS locks |
| **Engine Cutoff Spoof** | `spoof-engine`| `0x110` (Engine ECU) | 150 fps | Injects RPM=0 and engine shutdown status |
| **Payload Fuzzing** | `fuzz` | Randomized `0x001`-`0x7FE`| 800 fps | High-entropy payloads to trigger ECU memory faults |
| **Replay Attack** | `replay` | Recorded IDs | 1,000 fps | Re-transmits legitimate frames out of context |

---

## Getting Started & Usage Guide

### 1. Initialize Virtual CAN (`vcan0`)
On a Linux host with `can-utils`:
```bash
sudo bash scripts/setup_vcan.sh
```

### 2. Run Normal Multi-ECU Simulation
```bash
make bin/ecu_sim
./bin/ecu_sim -i vcan0 -m normal
```

### 3. Launch Malware & Attack Injection (Separate Terminal)
```bash
make bin/attack_injector

# Launch DoS Flood Attack
./bin/attack_injector -i vcan0 -m flood -c 2000 -r 3000

# Launch Spoofed Brake Override
./bin/attack_injector -i vcan0 -m spoof-brake -c 200 -r 150

# Launch Random Fuzzing
./bin/attack_injector -i vcan0 -m fuzz -c 500 -r 800
```

### 4. Run Automated Test Suite
```bash
pytest tests/ -v
```
