# CAN-Sentinel: Automotive ECU Intrusion Detection System

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20SocketCAN%20%7C%20Cross--Platform-blue.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%20%2F%20Python%203.10+-brightgreen.svg)](#)
[![ML](https://img.shields.io/badge/Model-Isolation%20Forest%20%28Scikit--Learn%29-orange.svg)](#)
[![Status](https://img.shields.io/badge/Phase%203-Completed-success.svg)](#)

CAN-Sentinel is an automotive Intrusion Detection System (IDS) and forensic diagnostic monitoring platform engineered for Controller Area Network (CAN) vehicle bus architectures. It combines low-level Linux SocketCAN C broadcasters/sniffers, a high-speed Unix Domain Socket IPC bridge, real-time streaming ML anomaly detection (Isolation Forest), heuristic rogue node localization, forensic JSON event logging, and verified 10,000+ fps zero-loss load resilience.

---

## Core Architecture & Implemented Modules

- **Virtual Interface & Environment Configuration**: Automated Linux `vcan0` setup and teardown management (`scripts/setup_vcan.sh`, `scripts/teardown_vcan.sh`).
- **Low-Level C SocketCAN Broadcaster**: `src/c/can_broadcaster.c` implementing Linux SocketCAN `PF_CAN`, `SOCK_RAW`, and `struct can_frame`.
- **Multi-Threaded C Multi-ECU Simulation**: `src/c/ecu_sim.c` with POSIX threads broadcasting realistic powertrain, chassis, brake, and body ECU telemetry.
- **High-Speed C Sniffer with Kernel Filters**: `src/c/sniffer.c` with zero-copy packet extraction, hardware ID filter masks, and IPC forwarding.
- **Inter-Process Communication (IPC) Bridge**: `src/c/ipc_bridge.c` and `src/ipc/ipc_server.py` streaming 24-byte binary frame structs across Unix Domain Sockets (`/tmp/can_sentinel.sock`) and TCP fallback.
- **Streaming Real-Time Inference Pipeline**: `src/detection/stream_detector.py` executing continuous sub-millisecond feature extraction and Isolation Forest inference.
- **Heuristic Scoring & Alert Engine**: `src/detection/alert_engine.py` pinpointing rogue IDs, compromised physical subsystems, and persisting structured forensic logs (`logs/alerts.json`).
- **High-Load Stress Testing**: `tests/stress_test.py` verifying 10,000+ frames/sec throughput with 0.0% packet loss.

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
│   │   ├── attack_injector.c      # Low-level C SocketCAN attack & malware injector
│   │   ├── sniffer.c              # High-speed C sniffer with SocketCAN ID filters
│   │   └── ipc_bridge.c           # High-speed C -> Python Unix socket IPC bridge
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
│   │   ├── train_isolation_forest.py # Isolation Forest trainer & inference engine
│   │   ├── evaluate.py            # Attack validation & performance metrics engine
│   │   └── model_manager.py       # Model lifecycle & serialization manager
│   ├── ipc/
│   │   └── ipc_server.py          # Multithreaded Unix/TCP binary IPC server
│   ├── detection/
│   │   ├── stream_detector.py     # Sub-millisecond real-time streaming detector
│   │   └── alert_engine.py        # Heuristic scoring, node localization & JSON logger
│   ├── defense/                   # Active error-frame mitigation (Phase 4)
│   └── ui/                        # Diagnostic dashboard & vehicle topology (Phase 4)
├── dataset/
│   ├── normal_traffic.csv         # Baseline normal vehicle telemetry dataset
│   └── attack_traffic.csv         # Labeled attack injection evaluation dataset
├── models/
│   └── model_metadata.json        # Serialized ML metadata, features, and threshold
├── logs/
│   └── alerts.json                # Structured forensic alert logs
└── tests/
    ├── test_broadcaster.py        # Frame packing and arbitration tests
    ├── test_sim.py                # Multi-ECU simulation & timing tests
    ├── test_parser.py             # Telemetry parser & entropy tests
    ├── test_logger.py             # CSV logger & schema tests
    ├── test_attack.py             # Attack simulation & burst tests
    ├── test_ml.py                 # Feature engineering & Isolation Forest tests
    ├── test_evaluation.py         # Evaluation & metrics tests
    ├── test_ipc.py                # IPC server & streaming detection tests
    ├── benchmark_latency.py       # Sub-millisecond latency audit
    └── stress_test.py             # 10,000+ fps load & buffer stress test
```

---

## Getting Started & Usage Guide

### 1. Run Real-Time Streaming Sniffer & Detection Pipeline
In Terminal 1 (Start Python Detection Engine):
```bash
python -m src.detection.stream_detector
```

In Terminal 2 (Start C Sniffer with IPC forwarding):
```bash
make bin/sniffer
./bin/sniffer -i vcan0 -s /tmp/can_sentinel.sock
```

In Terminal 3 (Start Multi-ECU Telemetry or Attacks):
```bash
# Normal vehicle driving
./bin/ecu_sim -i vcan0 -m normal

# Or launch attack injection
./bin/attack_injector -i vcan0 -m flood -c 1000 -r 2500
```

### 2. Run Stress Test Benchmark (10,000+ FPS Load)
```bash
python tests/stress_test.py
```

### 3. Run Automated Test Suite
```bash
pytest tests/ -v
```
