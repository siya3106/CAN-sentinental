#!/usr/bin/env bash
# ==============================================================================
# CAN-Sentinel: Virtual CAN (vcan0) Teardown Script
# Phase 1, Day 1: Environment & Virtual Interface Configuration
# ==============================================================================

set -e

INTERFACE="${1:-vcan0}"
UNLOAD_MODULE="${2:-0}"

# Terminal styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] CAN-Sentinel: Tearing down interface '${INTERFACE}'...${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root or with sudo privileges.${NC}"
    echo -e "Usage: sudo $0 [interface_name] [unload_module (0 or 1)]"
    exit 1
fi

if ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${YELLOW}[*] Bringing down interface '${INTERFACE}'...${NC}"
    ip link set down "$INTERFACE" 2>/dev/null || true
    echo -e "${YELLOW}[*] Deleting link '${INTERFACE}'...${NC}"
    ip link delete "$INTERFACE" 2>/dev/null || true
    echo -e "${GREEN}[+] Interface '${INTERFACE}' removed.${NC}"
else
    echo -e "${YELLOW}[!] Interface '${INTERFACE}' does not exist.${NC}"
fi

if [[ "$UNLOAD_MODULE" == "1" ]]; then
    echo -e "${YELLOW}[*] Unloading kernel module 'vcan'...${NC}"
    modprobe -r vcan 2>/dev/null || true
    echo -e "${GREEN}[+] Module 'vcan' unloaded.${NC}"
fi

echo -e "${GREEN}[SUCCESS] Teardown complete.${NC}"
