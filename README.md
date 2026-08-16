# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![ML](https://img.shields.io/badge/ML-Isolation%20Forest%20%28Scikit--Learn%29-orange.svg)](#)
[![Status](https://img.shields.io/badge/Milestone-Phase%201%20%28Day%203%20Completed%29-success.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters and sniffers, inter-process communication (IPC) streaming pipelines, machine learning anomaly detection using Isolation Forests with Shannon entropy & $\Delta t$ inter-arrival time features, active error-frame defense countermeasures, and a desktop diagnostic dashboard featuring interactive 2D vehicle topology visualization.

---

## 20-Day Phase Roadmap

| Phase | Focus | Days | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Environment Setup & Low-Level Traffic Simulation** | Days 1–5 | **In Progress (Days 1–3 Complete)** |
| **Phase 2** | **Attack Simulation & ML Anomaly Detection** | Days 6–10 | Planned |
| **Phase 3** | **Live IPC Integration & C Sniffer** | Days 11–15 | Planned |
| **Phase 4** | **Diagnostic Dashboard & Countermeasures** | Days 16–20 | Planned |

---

## Phase 1 Deliverables Breakdown

- [x] **Day 1**: Environment & Virtual Interface Configuration (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`, repository scaffolding).
  - **Commit 1**: `chore: initialize repository structure and vcan setup script`
- [x] **Day 2**: Raw C SocketCAN Broadcaster (`src/c/can_broadcaster.c`, `src/c/can_sentinel_common.h`).
  - `feat(can): implement raw C SocketCAN broadcaster and frame crafting engine`
- [x] **Day 3**: Multi-ECU Telemetry Simulation (`src/c/ecu_sim.c`, `src/sim/ecu_generator.py`, `src/sim/bus_emulator.py`).
  - **Commit 2**: `feat(sim): add multi-ECU telemetry broadcast in C`
- [ ] **Day 4**: Python SocketCAN Telemetry Parser (payload decoding & $\Delta t$ delta time).
- [ ] **Day 5**: Forensic CSV Data Logger (`dataset/normal_traffic.csv`).

---

## Repository Structure

```
can-sentinel/
├── README.md                      # Project documentation and architecture guide
├── Makefile                       # Build automation for C tools & test runners
├── requirements.txt               # Python package dependencies
├── scripts/
│   ├── setup_vcan.sh              # Day 1: Linux vcan0 initialization script
│   └── teardown_vcan.sh           # Day 1: vcan0 teardown & cleanup script
├── src/
│   ├── c/
│   │   ├── can_sentinel_common.h  # Common arbitration IDs, structs & formatting macros
│   │   ├── can_broadcaster.c      # Day 2: Low-level C SocketCAN broadcaster & frame crafter
│   │   └── ecu_sim.c              # Day 3: Multi-threaded C multi-ECU telemetry simulator
│   ├── sim/
│   │   ├── bus_emulator.py        # Day 3: Virtual bus abstraction & socketcan fallback
│   │   └── ecu_generator.py       # Day 3: Python multi-ECU physics and telemetry simulator
│   ├── parser/                    # Frame parsers & signal decoders
│   ├── logger/                    # Forensic CSV & JSON telemetry loggers
│   ├── attacks/                   # High-frequency flood, spoofing, & fuzzing engines
│   ├── ml/                        # Feature engineering & Isolation Forest training
│   ├── ipc/                       # Unix Domain Socket & TCP IPC streaming bridges
│   ├── detection/                 # Real-time streaming detector & heuristic alert engine
│   ├── defense/                   # Active error-frame mitigation & bus isolation
│   └── ui/                        # PyQt diagnostic dashboard & 2D vehicle topology
├── dataset/                       # Normal & attack telemetry datasets
├── models/                        # Serialized ML models (.joblib) & metadata
├── logs/                          # Forensic alert logs (alerts.json)
└── tests/
    ├── test_broadcaster.py        # Day 2: Frame packing and arbitration tests
    └── test_sim.py                # Day 3: Multi-ECU simulation & timing tests
```

---

## Multi-ECU Broadcast Architecture & Arbitration IDs

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

## Running Multi-ECU Telemetry Simulation

### 1. Build and Run C Multi-ECU Simulator
Compile the multi-threaded C simulator:
```bash
make bin/ecu_sim
# Or compile directly:
gcc -Wall -Wextra -O2 -Isrc/c src/c/ecu_sim.c -o bin/ecu_sim -pthread -lm
```

Execute the simulator on `vcan0` with dynamic driving profiles:
```bash
# Run normal driving cycle
./bin/ecu_sim -i vcan0 -m normal

# Run with verbose packet printing
./bin/ecu_sim -i vcan0 -v

# Run highway mode for 30 seconds
./bin/ecu_sim -i vcan0 -m highway -d 30
```

### 2. Run Python Simulation & Tests
```bash
# Run unit tests
pytest tests/ -v
```
