/**
 * @file can_sentinel_common.h
 * @brief Common definitions, arbitration IDs, and utility macros for CAN-Sentinel.
 *
 * Automotive ECU Intrusion Detection System
 */

#ifndef CAN_SENTINEL_COMMON_H
#define CAN_SENTINEL_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/can/error.h>
#else
/* Fallback definitions for non-Linux host development / linting */
#ifndef PF_CAN
#define PF_CAN 29
#define AF_CAN PF_CAN
#endif

#ifndef CAN_RAW
#define CAN_RAW 1
#endif

#ifndef CAN_MAX_DLC
#define CAN_MAX_DLC 8
#endif

#ifndef CAN_MAX_DLEN
#define CAN_MAX_DLEN 8
#endif

#ifndef CAN_EFF_FLAG
#define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
#endif

#ifndef CAN_RTR_FLAG
#define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
#endif

#ifndef CAN_ERR_FLAG
#define CAN_ERR_FLAG 0x20000000U /* error message frame */
#endif

#ifndef CAN_SFF_MASK
#define CAN_SFF_MASK 0x000007FFU /* standard frame format (SFF) */
#endif

#ifndef CAN_EFF_MASK
#define CAN_EFF_MASK 0x1FFFFFFFU /* extended frame format (EFF) */
#endif

#ifndef CAN_ERR_MASK
#define CAN_ERR_MASK 0x1FFFFFFFU /* omit EFF, RTR, ERR flags */
#endif

typedef uint32_t canid_t;

struct can_frame {
    canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
    uint8_t can_dlc; /* frame payload length in byte (0 .. 8) */
    uint8_t __pad;   /* padding */
    uint8_t __res0;  /* reserved / padding */
    uint8_t __res1;  /* reserved / padding */
    uint8_t data[CAN_MAX_DLEN] __attribute__((aligned(8)));
};

struct sockaddr_can {
    uint16_t can_family;
    int can_ifindex;
    union {
        struct { canid_t rx_id, tx_id; } tp;
    } can_addr;
};
#endif /* __linux__ */

/* ============================================================================
 * Standard Automotive ECU Arbitration IDs (Standard 11-bit)
 * ============================================================================ */
#define CAN_ID_BRAKE_OVERRIDE   0x0A0   /* Brake System / Critical ABS */
#define CAN_ID_ENGINE_RPM       0x110   /* Powertrain: Engine RPM */
#define CAN_ID_VEHICLE_SPEED    0x120   /* Powertrain: Vehicle Speed */
#define CAN_ID_ENGINE_TEMP      0x130   /* Powertrain: Coolant / Engine Temp */
#define CAN_ID_TRANSMISSION     0x180   /* Transmission: Gear & Torque */
#define CAN_ID_STEERING_ANGLE   0x1E5   /* Chassis: Steering Wheel Angle */
#define CAN_ID_BODY_DOORS       0x230   /* Body ECU: Doors, Locks, Windows */
#define CAN_ID_BODY_CLIMATE     0x240   /* Body ECU: HVAC & Ambient Temp */
#define CAN_ID_LIGHTING         0x270   /* Body ECU: Headlights / Turn Signals */
#define CAN_ID_INFOTAINMENT     0x350   /* Telematics / Infotainment Node */
#define CAN_ID_DIAGNOSTIC_REQ   0x7DF   /* OBD-II Broadcast Request */
#define CAN_ID_DIAGNOSTIC_RESP  0x7E8   /* Engine ECU Diagnostic Response */

/* ============================================================================
 * Standard IPC Frame Structure for Python Engine Streaming
 * ============================================================================ */
#pragma pack(push, 1)
typedef struct {
    uint64_t timestamp_us; /* Microsecond timestamp since Unix epoch */
    uint32_t can_id;       /* 11-bit or 29-bit CAN ID + flags */
    uint8_t  dlc;          /* Data Length Code (0-8) */
    uint8_t  data[8];      /* Frame payload bytes */
    uint8_t  is_extended;  /* 1 if 29-bit extended ID, else 0 */
    uint8_t  is_error;     /* 1 if CAN error frame, else 0 */
    uint8_t  is_rtr;       /* 1 if Remote Transmission Request, else 0 */
} can_sentinel_ipc_frame_t;
#pragma pack(pop)

/* ANSI Terminal Colors */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_BOLD    "\x1b[1m"

/**
 * @brief Get current timestamp in microseconds.
 */
static inline uint64_t can_get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000000ULL) + ((uint64_t)ts.tv_nsec / 1000ULL);
}

/**
 * @brief Format and print a standard CAN frame to standard output.
 */
static inline void can_print_frame(const struct can_frame *frame, const char *prefix) {
    uint32_t id = frame->can_id & (frame->can_id & CAN_EFF_FLAG ? CAN_EFF_MASK : CAN_SFF_MASK);
    int is_eff = (frame->can_id & CAN_EFF_FLAG) ? 1 : 0;
    int is_err = (frame->can_id & CAN_ERR_FLAG) ? 1 : 0;

    printf("%s [%s] ID: 0x%0*X  DLC: %d  Data: [ ",
           prefix ? prefix : "[CAN]",
           is_err ? "ERR" : (is_eff ? "EXT" : "STD"),
           is_eff ? 8 : 3,
           id,
           frame->can_dlc);

    for (int i = 0; i < frame->can_dlc && i < CAN_MAX_DLEN; i++) {
        printf("%02X ", frame->data[i]);
    }
    for (int i = frame->can_dlc; i < CAN_MAX_DLEN; i++) {
        printf(".. ");
    }
    printf("]\n");
}

#endif /* CAN_SENTINEL_COMMON_H */
