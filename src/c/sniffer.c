/**
 * @file sniffer.c
 * @brief High-Speed Low-Latency SocketCAN Sniffer for CAN-Sentinel.
 * Phase 3, Day 11: High-Speed C Sniffer
 *
 * Implements low-overhead SocketCAN sniffing, hardware/kernel-level frame filtering,
 * microsecond timestamping, and optional IPC streaming forwarder.
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
#include <linux/can.h>
#include <linux/can/raw.h>
#endif

static volatile int g_sniffer_running = 1;
static uint64_t g_packets_captured = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_sniffer_running = 0;
}

/**
 * @brief Open a SocketCAN socket with optional hardware filter masks.
 */
static int open_sniffer_socket(const char *iface_name, canid_t filter_id, canid_t filter_mask, int enable_filter) {
#ifdef __linux__
    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror(ANSI_COLOR_RED "[ERROR] socket(PF_CAN, SOCK_RAW) failed" ANSI_COLOR_RESET);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, ANSI_COLOR_RED "[ERROR] Interface '%s' not found.\n" ANSI_COLOR_RESET, iface_name);
        close(sock);
        return -1;
    }

    /* Apply kernel-level SocketCAN filters if requested */
    if (enable_filter) {
        struct can_filter rfilter[1];
        rfilter[0].can_id   = filter_id;
        rfilter[0].can_mask = filter_mask;
        if (setsockopt(sock, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter)) < 0) {
            perror(ANSI_COLOR_YELLOW "[!] Warning: Failed to set CAN_RAW_FILTER" ANSI_COLOR_RESET);
        } else {
            printf(ANSI_COLOR_CYAN "[*] Applied CAN Filter: ID=0x%03X, Mask=0x%03X\n" ANSI_COLOR_RESET, filter_id, filter_mask);
        }
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror(ANSI_COLOR_RED "[ERROR] bind() to interface failed" ANSI_COLOR_RESET);
        close(sock);
        return -1;
    }

    return sock;
#else
    fprintf(stderr, ANSI_COLOR_YELLOW "[MOCK] Simulated sniffer socket for '%s'\n" ANSI_COLOR_RESET, iface_name);
    return 300;
#endif
}

/**
 * @brief Open a Unix Domain Socket connection to the Python engine.
 */
static int open_ipc_socket(const char *sock_path) {
#ifdef __linux__
    int ipc_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc_sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(ipc_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(ipc_sock);
        return -1;
    }
    return ipc_sock;
#else
    (void)sock_path;
    return -1;
#endif
}

static void print_sniffer_usage(const char *prog_name) {
    printf(ANSI_COLOR_BOLD "CAN-Sentinel: High-Speed C SocketCAN Sniffer (Phase 3, Day 11)\n" ANSI_COLOR_RESET);
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --iface <name>       CAN interface to sniff (default: vcan0)\n");
    printf("  -f, --filter <id>        Filter specific CAN ID in hex (e.g. 0x110)\n");
    printf("  -m, --mask <hex_mask>    Filter bitmask in hex (default: 0x7FF for exact ID)\n");
    printf("  -s, --ipc-socket <path>  Stream captured frames to Unix socket (e.g. /tmp/can_sentinel.sock)\n");
    printf("  -c, --count <num>        Number of frames to capture (0 = infinite, default: 0)\n");
    printf("  -q, --quiet              Suppress per-packet stdout printing\n");
    printf("  -h, --help               Display this help guide\n\n");
}

int main(int argc, char *argv[]) {
    const char *iface = "vcan0";
    canid_t filter_id = 0;
    canid_t filter_mask = CAN_SFF_MASK;
    int enable_filter = 0;
    const char *ipc_path = NULL;
    uint64_t max_count = 0;
    int quiet = 0;

    static struct option long_options[] = {
        {"iface",      required_argument, 0, 'i'},
        {"filter",     required_argument, 0, 'f'},
        {"mask",       required_argument, 0, 'm'},
        {"ipc-socket", required_argument, 0, 's'},
        {"count",      required_argument, 0, 'c'},
        {"quiet",      no_argument,       0, 'q'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:f:m:s:c:qh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'f':
                filter_id = (canid_t)strtoul(optarg, NULL, 0);
                enable_filter = 1;
                break;
            case 'm':
                filter_mask = (canid_t)strtoul(optarg, NULL, 0);
                break;
            case 's': ipc_path = optarg; break;
            case 'c': max_count = (uint64_t)strtoull(optarg, NULL, 10); break;
            case 'q': quiet = 1; break;
            case 'h':
            default:
                print_sniffer_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "       CAN-Sentinel: High-Speed C Sniffer           \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf("[*] Sniffing Interface : %s\n", iface);
    if (enable_filter) {
        printf("[*] Kernel Filter      : ID=0x%03X, Mask=0x%03X\n", filter_id, filter_mask);
    }
    if (ipc_path) {
        printf("[*] IPC Streaming Link : %s\n", ipc_path);
    }
    printf(ANSI_COLOR_GREEN "[+] Listening for CAN frames (Press Ctrl+C to stop)...\n" ANSI_COLOR_RESET);

    int can_sock = open_sniffer_socket(iface, filter_id, filter_mask, enable_filter);
    if (can_sock < 0) return 1;

    int ipc_sock = -1;
    if (ipc_path) {
        ipc_sock = open_ipc_socket(ipc_path);
        if (ipc_sock >= 0) {
            printf(ANSI_COLOR_GREEN "[+] Connected to Python IPC socket: %s\n" ANSI_COLOR_RESET, ipc_path);
        } else {
            printf(ANSI_COLOR_YELLOW "[!] Warning: IPC socket connect failed (%s). Continuing console sniff...\n" ANSI_COLOR_RESET, strerror(errno));
        }
    }

    uint64_t start_time = can_get_timestamp_us();

    while (g_sniffer_running && (max_count == 0 || g_packets_captured < max_count)) {
        struct can_frame frame;
#ifdef __linux__
        ssize_t nbytes = read(can_sock, &frame, sizeof(struct can_frame));
        if (nbytes < 0) {
            if (errno == EINTR) break;
            perror(ANSI_COLOR_RED "[ERROR] read() from SocketCAN failed" ANSI_COLOR_RESET);
            break;
        }
        if (nbytes < (ssize_t)sizeof(struct can_frame)) {
            continue;
        }
#else
        /* Mock simulation tick */
        usleep(20000);
        can_craft_frame(&frame, 0x110, 4, (const uint8_t*)"\x09\xC4\x28\x01", 0, 0);
#endif

        g_packets_captured++;
        uint64_t ts_us = can_get_timestamp_us();

        /* Print frame if not quiet */
        if (!quiet) {
            can_print_frame(&frame, ANSI_COLOR_CYAN "[SNIFF]" ANSI_COLOR_RESET);
        }

        /* Forward to IPC socket if connected */
        if (ipc_sock >= 0) {
            can_sentinel_ipc_frame_t ipc_frame;
            memset(&ipc_frame, 0, sizeof(ipc_frame));
            ipc_frame.timestamp_us = ts_us;
            ipc_frame.can_id = frame.can_id & (frame.can_id & CAN_EFF_FLAG ? CAN_EFF_MASK : CAN_SFF_MASK);
            ipc_frame.dlc = frame.can_dlc;
            memcpy(ipc_frame.data, frame.data, (frame.can_dlc <= 8) ? frame.can_dlc : 8);
            ipc_frame.is_extended = (frame.can_id & CAN_EFF_FLAG) ? 1 : 0;
            ipc_frame.is_error = (frame.can_id & CAN_ERR_FLAG) ? 1 : 0;
            ipc_frame.is_rtr = (frame.can_id & CAN_RTR_FLAG) ? 1 : 0;

#ifdef __linux__
            if (write(ipc_sock, &ipc_frame, sizeof(ipc_frame)) < 0) {
                close(ipc_sock);
                ipc_sock = -1;
            }
#endif
        }
    }

    uint64_t end_time = can_get_timestamp_us();
    double elapsed_sec = (double)(end_time - start_time) / 1000000.0;

    printf("\n" ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "[+] Sniffer stopped.\n" ANSI_COLOR_RESET);
    printf("    Frames Captured        : %llu\n", (unsigned long long)g_packets_captured);
    printf("    Elapsed Time           : %.3f seconds\n", elapsed_sec);
    printf("    Capture Throughput     : %.1f frames/sec\n",
           elapsed_sec > 0 ? (double)g_packets_captured / elapsed_sec : 0.0);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);

#ifdef __linux__
    close(can_sock);
    if (ipc_sock >= 0) close(ipc_sock);
#endif
    return 0;
}
