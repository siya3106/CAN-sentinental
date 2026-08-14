#!/usr/bin/env bash
# ==============================================================================
# CAN-Sentinel: Virtual CAN (vcan0) Setup Script
# Phase 1, Day 1: Environment & Virtual Interface Configuration
# ==============================================================================

set -e

# Default settings
INTERFACE="${1:-vcan0}"
ENABLE_FD="${2:-0}" # Set to 1 to enable CAN-FD MTU support

# Terminal styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}       CAN-Sentinel: Virtual CAN Interface Setup    ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Check for root / sudo privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root or with sudo privileges.${NC}"
    echo -e "Usage: sudo $0 [interface_name] [enable_fd (0 or 1)]"
    exit 1
fi

# 1. Load the Linux kernel virtual CAN module
echo -e "${YELLOW}[*] Loading Linux 'vcan' kernel module...${NC}"
if modprobe vcan; then
    echo -e "${GREEN}[+] Module 'vcan' loaded successfully.${NC}"
else
    echo -e "${RED}[ERROR] Failed to load kernel module 'vcan'. Ensure your Linux kernel supports SocketCAN.${NC}"
    exit 1
fi

# 2. Check if the interface already exists
if ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${YELLOW}[!] Interface '${INTERFACE}' already exists. Re-initializing...${NC}"
    ip link set down "$INTERFACE" 2>/dev/null || true
    ip link delete "$INTERFACE" 2>/dev/null || true
fi

# 3. Create the virtual CAN link
echo -e "${YELLOW}[*] Creating virtual CAN link: ${INTERFACE}...${NC}"
ip link add dev "$INTERFACE" type vcan

# 4. Configure MTU for CAN-FD if requested
if [[ "$ENABLE_FD" == "1" ]]; then
    echo -e "${YELLOW}[*] Configuring interface for CAN-FD (MTU 72)...${NC}"
    ip link set "$INTERFACE" mtu 72
fi

# 5. Bring the interface UP
echo -e "${YELLOW}[*] Bringing up interface: ${INTERFACE}...${NC}"
ip link set up "$INTERFACE"

# 6. Verify interface status
echo -e "${YELLOW}[*] Verifying interface status:${NC}"
ip -details link show "$INTERFACE"

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}[SUCCESS] Virtual CAN interface '${INTERFACE}' is UP and ready!${NC}"
echo -e "${GREEN}You can now sniff traffic using: candump ${INTERFACE}${NC}"
echo -e "${GREEN}You can generate test frames using: cansend ${INTERFACE} 123#DEADBEEF${NC}"
echo -e "${GREEN}====================================================${NC}"
