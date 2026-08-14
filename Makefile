# ==============================================================================
# CAN-Sentinel Makefile
# Automotive ECU Intrusion Detection System
# ==============================================================================

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -pthread -Isrc/c
LDFLAGS ?= -pthread

SRC_C_DIR = src/c
BIN_DIR = bin

TARGETS = \
	$(BIN_DIR)/can_broadcaster \
	$(BIN_DIR)/ecu_sim \
	$(BIN_DIR)/attack_injector \
	$(BIN_DIR)/sniffer \
	$(BIN_DIR)/ipc_bridge \
	$(BIN_DIR)/error_frame_injector

.PHONY: all setup-vcan teardown-vcan clean help install-deps test

all: $(BIN_DIR) $(TARGETS)
	@echo "[+] All CAN-Sentinel C binaries built successfully."

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(BIN_DIR)/%: $(SRC_C_DIR)/%.c
	@if [ -f $< ]; then \
		echo "[*] Compiling $< -> $@"; \
		$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS); \
	fi

setup-vcan:
	@echo "[*] Initializing Virtual CAN interface (vcan0)..."
	sudo bash scripts/setup_vcan.sh vcan0

teardown-vcan:
	@echo "[*] Tearing down Virtual CAN interface..."
	sudo bash scripts/teardown_vcan.sh vcan0

install-deps:
	@echo "[*] Installing Python dependencies..."
	pip install -r requirements.txt

test:
	@echo "[*] Running automated test suite..."
	pytest tests/ -v

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -rf $(BIN_DIR) *.o *.sock
	find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "[+] Clean complete."

help:
	@echo "CAN-Sentinel Build & Run Targets:"
	@echo "  make all           - Build all C socket tools into bin/"
	@echo "  make setup-vcan    - Bring up Linux virtual CAN interface (vcan0)"
	@echo "  make teardown-vcan - Teardown virtual CAN interface"
	@echo "  make install-deps  - Install Python dependencies from requirements.txt"
	@echo "  make test          - Run Python test suite"
	@echo "  make clean         - Remove binaries and cache artifacts"
