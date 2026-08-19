# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![ML](https://img.shields.io/badge/Model-Isolation%20Forest%20%28Scikit--Learn%29-orange.svg)](#)
[![Status](https://img.shields.io/badge/Phase%202-Day%208%20Complete-blue.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and forensic diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters and multi-threaded ECU simulators, high-speed telemetry frame parsing with microsecond inter-arrival delta time ($\Delta t$) tracking, Shannon entropy estimation, forensic CSV telemetry data logging, malware/attack injection suites, and an unsupervised **Isolation Forest** machine learning detection engine.

---

## Core Architecture & Implemented Deliverables

- **Virtual Interface & Environment Configuration**: Automated Linux `vcan0` setup and teardown management (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`).
- **Low-Level C SocketCAN Broadcaster**: `src/c/can_broadcaster.c` implementing Linux SocketCAN `PF_CAN`, `SOCK_RAW`, and `struct can_frame` with frequency-controlled bursts.
- **Multi-Threaded C Multi-ECU Simulation**: `src/c/ecu_sim.c` with POSIX threads broadcasting realistic powertrain, chassis, brake, and body ECU telemetry.
- **Cross-Platform Bus Emulation & ECU Generator**: `src/sim/bus_emulator.py` and `src/sim/ecu_generator.py` providing in-memory virtual CAN broadcasting.
- **SocketCAN Telemetry Parser & Signal Decoder**: `src/parser/telemetry_parser.py` parsing raw frames, decoding vehicle DBC signals, and computing per-ID delta times ($\Delta t$) and Shannon entropy.
- **Forensic CSV Telemetry Data Logger**: `src/logger/csv_logger.py` streaming parsed telemetry to `dataset/normal_traffic.csv` for baseline modeling.
- **Malware & Attack Injection Suite**: `src/c/attack_injector.c` and `src/attacks/attack_suite.py` simulating high-frequency DoS flooding, Brake/Engine spoofing, randomized payload fuzzing, and replay attacks.
- **Feature Engineering & Preprocessing Pipeline**: `src/ml/features.py` extracting 10 temporal, statistical, and information-theoretic features per frame.
- **Unsupervised Isolation Forest IDS**: `src/ml/train_isolation_forest.py` with hyperparameter tuning (`n_estimators=150`, `contamination=0.03`) for sub-millisecond anomaly detection.

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
│   ├── ml/
│   │   ├── features.py            # Feature engineering & sliding-window preprocessor
│   │   └── train_isolation_forest.py # Isolation Forest trainer & inference engine
│   ├── ipc/                       # Socket IPC streaming bridges
│   ├── detection/                 # Real-time streaming detector
│   ├── defense/                   # Active error-frame mitigation
│   └── ui/                        # Diagnostic dashboard & vehicle topology
├── dataset/
│   ├── normal_traffic.csv         # Baseline normal vehicle telemetry dataset
│   └── attack_traffic.csv         # Labeled attack injection evaluation dataset
├── models/
│   └── model_metadata.json        # Serialized ML metadata, features, and threshold
├── logs/                          # Forensic alert logs
└── tests/
    ├── test_broadcaster.py        # Frame packing and arbitration tests
    ├── test_sim.py                # Multi-ECU simulation & timing tests
    ├── test_parser.py             # Telemetry parser & entropy tests
    ├── test_logger.py             # CSV logger & schema tests
    ├── test_attack.py             # Attack simulation & burst tests
    └── test_ml.py                 # Feature engineering & Isolation Forest tests
```

---

## Machine Learning Feature Matrix

The feature extraction engine extracts 10 features per incoming CAN frame:

| Feature Index | Feature Name | Description | Purpose in Anomaly Detection |
| :--- | :--- | :--- | :--- |
| `0` | `can_id` | Numeric Arbitration Identifier | Detects unauthorized or rogue IDs |
| `1` | `dlc` | Data Length Code (0–8) | Identifies payload length anomalies |
| `2` | `delta_t` | Per-ID inter-arrival delta time (s) | Flags high-frequency flood & timing jitter |
| `3` | `global_delta_t` | Global bus inter-frame delta time (s)| Measures overall bus congestion |
| `4` | `entropy` | Shannon entropy of payload bytes | Identifies random fuzzing and encrypted payloads |
| `5` | `byte_mean` | Arithmetic mean of payload bytes | Detects constant or skewed payload injections |
| `6` | `byte_variance` | Variance of payload bytes | Measures byte dispersion |
| `7` | `id_freq_window` | Message count in rolling window ($W=50$) | Detects DoS bus monopolization |
| `8` | `id_ratio_window`| Ratio of target ID in window ($N_{ID} / W$) | Detects bus starvation of legitimate ECUs |
| `9` | `payload_change_rate` | Byte difference vs previous frame | Detects erratic spoofed signal mutations |

---

## Getting Started & Usage Guide

### 1. Train the Isolation Forest IDS Model
```bash
python -m src.ml.train_isolation_forest \
  --train dataset/normal_traffic.csv \
  --eval dataset/attack_traffic.csv \
  --output models/isolation_forest.joblib \
  --meta models/model_metadata.json
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
```

### 4. Run Automated Test Suite
```bash
pytest tests/ -v
```
