# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![ML](https://img.shields.io/badge/ML-Isolation%20Forest%20%28Scikit--Learn%29-orange.svg)](#)
[![Status](https://img.shields.io/badge/Milestone-Phase%201%20%28Day%202%20Completed%29-success.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters and sniffers, inter-process communication (IPC) streaming pipelines, machine learning anomaly detection using Isolation Forests with Shannon entropy & $\Delta t$ inter-arrival time features, active error-frame defense countermeasures, and a desktop diagnostic dashboard featuring interactive 2D vehicle topology visualization.

---

## 20-Day Phase Roadmap

| Phase | Focus | Days | Status |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Environment Setup & Low-Level Traffic Simulation** | Days 1–5 | **In Progress (Days 1–2 Complete)** |
| **Phase 2** | **Attack Simulation & ML Anomaly Detection** | Days 6–10 | Planned |
| **Phase 3** | **Live IPC Integration & C Sniffer** | Days 11–15 | Planned |
| **Phase 4** | **Diagnostic Dashboard & Countermeasures** | Days 16–20 | Planned |

---

## Phase 1 Deliverables Breakdown

- [x] **Day 1**: Environment & Virtual Interface Configuration (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`, repository scaffolding).
  - **Commit 1**: `chore: initialize repository structure and vcan setup script`
- [x] **Day 2**: Raw C SocketCAN Broadcaster (`src/c/can_broadcaster.c`, `src/c/can_sentinel_common.h`).
  - **Commit 2**: `feat(can): implement raw C SocketCAN broadcaster and frame crafting engine`
- [ ] **Day 3**: Multi-ECU Telemetry Simulation (Engine `0x110`/`0x120`, Body `0x230`, Transmission `0x180`).
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
│   │   └── can_broadcaster.c      # Day 2: Low-level C SocketCAN broadcaster & frame crafter
│   ├── sim/                       # Multi-ECU telemetry generators & bus emulators
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
    └── test_broadcaster.py        # Day 2: Frame packing and arbitration tests
```

---

## Day 1 Setup Guide: Virtual CAN Interface

### 1. Prerequisites (Linux / WSL2 / Docker)
On a Linux host (e.g., Ubuntu/Debian), install the standard SocketCAN utilities:
```bash
sudo apt-get update
sudo apt-get install -y can-utils iproute2 build-essential
```

### 2. Initialize Virtual CAN (`vcan0`)
Run the automated initialization script to load the `vcan` kernel module and bring up the `vcan0` interface:
```bash
sudo bash scripts/setup_vcan.sh
```

To enable CAN-FD (Flexible Data-rate MTU 72):
```bash
sudo bash scripts/setup_vcan.sh vcan0 1
```

### 3. Verify Interface Status
Inspect the network link using `iproute2` or `candump`:
```bash
ip link show vcan0
```

---

## Day 2 Guide: Raw C SocketCAN Broadcaster

### 1. Build C Broadcaster
Compile using `make`:
```bash
make bin/can_broadcaster
# Or compile directly:
gcc -Wall -Wextra -O2 -Isrc/c src/c/can_broadcaster.c -o bin/can_broadcaster -pthread
```

### 2. Broadcast CAN Frames
Send single or periodic CAN frames onto `vcan0`:

```bash
# Broadcast Engine RPM (ID: 0x110, Payload: 0x09C4 / 2500 RPM) at 50 Hz (20ms period)
./bin/can_broadcaster -i vcan0 -d 0x110 -p 09C40100 -c 100 -r 50

# Broadcast Speed (ID: 0x120) every 100ms
./bin/can_broadcaster -i vcan0 -d 0x120 -p 4500 -t 100

# Run dynamic multi-ECU telemetry demonstration generator
./bin/can_broadcaster -i vcan0 -m
```

### 3. Sniff Broadcasted Frames
In a separate terminal:
```bash
candump vcan0
```

---

## Python Environment Setup
```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```
