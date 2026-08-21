/**
 * @file ipc_bridge.c
 * @brief High-Performance C to Python IPC Bridge for CAN-Sentinel.
 * Phase 3, Day 12: Inter-Process Communication (IPC) Bridge
 *
 * Captures raw CAN frames from kernel SocketCAN and streams 24-byte binary
 * structs across a Unix Domain Socket (/tmp/can_sentinel.sock) to the Python AI engine.
 */

#include "can_sentinel_common.h"
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#ifndef _WIN32
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#endif

static volatile int g_bridge_running = 1;
static uint64_t g_frames_bridged = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_bridge_running = 0;
}

int main(int argc, char *argv[]) {
    const char *iface = "vcan0";
    const char *ipc_path = "/tmp/can_sentinel.sock";
    int use_tcp = 0;
    int tcp_port = 5555;

    static struct option long_options[] = {
        {"iface",    required_argument, 0, 'i'},
        {"socket",   required_argument, 0, 's'},
        {"tcp",      required_argument, 0, 't'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:s:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 's': ipc_path = optarg; break;
            case 't':
                use_tcp = 1;
                tcp_port = atoi(optarg);
                break;
            case 'h':
            default:
                printf("Usage: %s [-i iface] [-s unix_socket_path] [-t tcp_port]\n", argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "       CAN-Sentinel: C -> Python IPC Bridge         \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf("[*] CAN Interface : %s\n", iface);
    if (use_tcp) {
        printf("[*] IPC Channel   : TCP localhost:%d\n", tcp_port);
    } else {
        printf("[*] IPC Channel   : Unix Domain Socket (%s)\n", ipc_path);
    }

#ifdef __linux__
    /* 1. Open SocketCAN */
    int can_sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_sock < 0) {
        perror(ANSI_COLOR_RED "[ERROR] SocketCAN create failed" ANSI_COLOR_RESET);
        return 1;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(can_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror(ANSI_COLOR_RED "[ERROR] Interface not found" ANSI_COLOR_RESET);
        close(can_sock);
        return 1;
    }

    struct sockaddr_can caddr;
    memset(&caddr, 0, sizeof(caddr));
    caddr.can_family = AF_CAN;
    caddr.can_ifindex = ifr.ifr_ifindex;
    if (bind(can_sock, (struct sockaddr *)&caddr, sizeof(caddr)) < 0) {
        perror(ANSI_COLOR_RED "[ERROR] Bind to CAN failed" ANSI_COLOR_RESET);
        close(can_sock);
        return 1;
    }

    /* 2. Connect to Python IPC Server */
    int ipc_sock = -1;
    if (use_tcp) {
        ipc_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in taddr;
        memset(&taddr, 0, sizeof(taddr));
        taddr.sin_family = AF_INET;
        taddr.sin_port = htons(tcp_port);
        inet_pton(AF_INET, "127.0.0.1", &taddr.sin_addr);
        if (connect(ipc_sock, (struct sockaddr *)&taddr, sizeof(taddr)) < 0) {
            perror(ANSI_COLOR_RED "[ERROR] TCP IPC connect failed" ANSI_COLOR_RESET);
            close(can_sock);
            close(ipc_sock);
            return 1;
        }
    } else {
        ipc_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un uaddr;
        memset(&uaddr, 0, sizeof(uaddr));
        uaddr.sun_family = AF_UNIX;
        strncpy(uaddr.sun_path, ipc_path, sizeof(uaddr.sun_path) - 1);
        if (connect(ipc_sock, (struct sockaddr *)&uaddr, sizeof(uaddr)) < 0) {
            fprintf(stderr, ANSI_COLOR_RED "[ERROR] Unix socket connect to '%s' failed: %s\n" ANSI_COLOR_RESET,
                    ipc_path, strerror(errno));
            close(can_sock);
            close(ipc_sock);
            return 1;
        }
    }

    printf(ANSI_COLOR_GREEN "[+] IPC Bridge active! Streaming raw frame structs to Python engine...\n" ANSI_COLOR_RESET);

    while (g_bridge_running) {
        struct can_frame frame;
        ssize_t n = read(can_sock, &frame, sizeof(struct can_frame));
        if (n <= 0) {
            if (errno == EINTR) break;
            break;
        }

        can_sentinel_ipc_frame_t pkt;
        pkt.timestamp_us = can_get_timestamp_us();
        pkt.can_id = frame.can_id & (frame.can_id & CAN_EFF_FLAG ? CAN_EFF_MASK : CAN_SFF_MASK);
        pkt.dlc = frame.can_dlc;
        memcpy(pkt.data, frame.data, 8);
        pkt.is_extended = (frame.can_id & CAN_EFF_FLAG) ? 1 : 0;
        pkt.is_error = (frame.can_id & CAN_ERR_FLAG) ? 1 : 0;
        pkt.is_rtr = (frame.can_id & CAN_RTR_FLAG) ? 1 : 0;

        if (write(ipc_sock, &pkt, sizeof(pkt)) != sizeof(pkt)) {
            perror(ANSI_COLOR_RED "[ERROR] IPC write failed" ANSI_COLOR_RESET);
            break;
        }
        g_frames_bridged++;
    }

    close(can_sock);
    close(ipc_sock);
#else
    printf(ANSI_COLOR_YELLOW "[MOCK] Native IPC Bridge running in simulation mode.\n" ANSI_COLOR_RESET);
#endif

    printf(ANSI_COLOR_GREEN "[+] IPC Bridge terminated. Total frames bridged: %llu\n" ANSI_COLOR_RESET,
           (unsigned long long)g_frames_bridged);
    return 0;
}
