/**
 * @file can_broadcaster.c
 * @brief Raw C SocketCAN Broadcaster for CAN-Sentinel.
 * Phase 1, Day 2: Low-level C SocketCAN Broadcaster
 *
 * Implements low-level SocketCAN frame crafting and transmission via PF_CAN / SOCK_RAW.
 */

#include "can_sentinel_common.h"
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#ifndef _WIN32
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <unistd.h>
#endif

/* Global state for signal handling */
static volatile int g_running = 1;
static uint64_t g_frames_sent = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Open and bind a raw SocketCAN socket to the specified network interface.
 * @param iface_name Network interface name (e.g., "vcan0", "can0").
 * @return Socket file descriptor on success, or -1 on error.
 */
int can_open_socket(const char *iface_name) {
#ifdef __linux__
    int sock;
    struct sockaddr_can addr;
    struct ifreq ifr;

    /* 1. Create a raw CAN socket */
    sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror(ANSI_COLOR_RED "[ERROR] socket(PF_CAN, SOCK_RAW) failed" ANSI_COLOR_RESET);
        return -1;
    }

    /* 2. Resolve interface name to interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, ANSI_COLOR_RED "[ERROR] Interface '%s' not found: %s\n" ANSI_COLOR_RESET,
                iface_name, strerror(errno));
        close(sock);
        return -1;
    }

    /* 3. Bind the socket to the CAN interface */
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror(ANSI_COLOR_RED "[ERROR] bind() to SocketCAN interface failed" ANSI_COLOR_RESET);
        close(sock);
        return -1;
    }

    return sock;
#else
    fprintf(stderr, ANSI_COLOR_YELLOW "[MOCK] Native SocketCAN requires Linux kernel. Simulated on non-Linux host for interface: %s\n" ANSI_COLOR_RESET, iface_name);
    return 100; /* Simulated socket descriptor */
#endif
}

/**
 * @brief Craft a standard or extended CAN frame.
 * @param frame Pointer to target can_frame struct.
 * @param can_id Arbitration ID (11-bit or 29-bit).
 * @param dlc Data Length Code (0..8).
 * @param data Array of payload bytes.
 * @param is_extended Set to 1 for extended 29-bit CAN ID.
 * @param is_rtr Set to 1 for Remote Transmission Request.
 * @return 0 on success, -1 on invalid parameters.
 */
int can_craft_frame(struct can_frame *frame, uint32_t can_id, uint8_t dlc,
                    const uint8_t *data, int is_extended, int is_rtr) {
    if (!frame) return -1;
    if (dlc > CAN_MAX_DLEN) dlc = CAN_MAX_DLEN;

    memset(frame, 0, sizeof(struct can_frame));

    frame->can_dlc = dlc;

    /* Apply CAN identifier and flags */
    if (is_extended) {
        frame->can_id = (can_id & CAN_EFF_MASK) | CAN_EFF_FLAG;
    } else {
        frame->can_id = (can_id & CAN_SFF_MASK);
    }

    if (is_rtr) {
        frame->can_id |= CAN_RTR_FLAG;
    }

    if (data && dlc > 0) {
        memcpy(frame->data, data, dlc);
    }

    return 0;
}

/**
 * @brief Transmit a raw CAN frame onto the bus.
 * @param sock SocketCAN file descriptor.
 * @param frame Pointer to the frame to transmit.
 * @return Number of bytes written on success, or -1 on error.
 */
int can_send_frame(int sock, const struct can_frame *frame) {
    if (!frame) return -1;

#ifdef __linux__
    ssize_t nbytes = write(sock, frame, sizeof(struct can_frame));
    if (nbytes != sizeof(struct can_frame)) {
        perror(ANSI_COLOR_RED "[ERROR] write() to SocketCAN failed" ANSI_COLOR_RESET);
        return -1;
    }
    return (int)nbytes;
#else
    (void)sock;
    /* Simulated non-Linux transmission output */
    return (int)sizeof(struct can_frame);
#endif
}

/**
 * @brief Parse a hexadecimal string into an array of bytes.
 * Supports formats like "11223344", "11 22 33 44", or "0x11,0x22".
 */
int can_parse_hex_payload(const char *hex_str, uint8_t *data, uint8_t *dlc) {
    if (!hex_str || !data || !dlc) return -1;

    size_t len = strlen(hex_str);
    int byte_count = 0;
    char clean_hex[32] = {0};
    int clean_len = 0;

    for (size_t i = 0; i < len && clean_len < 16; i++) {
        char c = hex_str[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            clean_hex[clean_len++] = c;
        }
    }

    for (int i = 0; i < clean_len; i += 2) {
        char byte_buf[3] = { clean_hex[i], (i + 1 < clean_len) ? clean_hex[i + 1] : '0', '\0' };
        data[byte_count++] = (uint8_t)strtoul(byte_buf, NULL, 16);
        if (byte_count >= CAN_MAX_DLEN) break;
    }

    *dlc = (uint8_t)byte_count;
    return byte_count;
}

/**
 * @brief High-precision sleep in milliseconds.
 */
static void sleep_ms(long ms) {
    if (ms <= 0) return;
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

/**
 * @brief Print command-line usage instructions.
 */
static void print_usage(const char *prog_name) {
    printf(ANSI_COLOR_BOLD "CAN-Sentinel: Raw C SocketCAN Broadcaster (Phase 1, Day 2)\n" ANSI_COLOR_RESET);
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --iface <name>       Target CAN interface (default: vcan0)\n");
    printf("  -d, --id <hex_id>        CAN Arbitration ID (e.g., 0x110 or 110, default: 0x110)\n");
    printf("  -p, --payload <hex>      Payload bytes in hex (e.g., 'DEADBEEF', default: '00 00 00 00')\n");
    printf("  -l, --dlc <len>          Payload length (0..8, auto-detected from payload if omitted)\n");
    printf("  -c, --count <num>        Number of frames to send (0 = infinite loop, default: 1)\n");
    printf("  -r, --rate <hz>          Transmission rate in Hz (e.g., 50 for 50Hz / 20ms interval)\n");
    printf("  -t, --interval <ms>      Interval between frames in milliseconds (default: 100ms)\n");
    printf("  -e, --extended           Use 29-bit Extended Frame Format (EFF)\n");
    printf("  -m, --multi-demo         Run dynamic multi-ECU sample pattern generator\n");
    printf("  -h, --help               Display this help message\n\n");
    printf("Examples:\n");
    printf("  %s -i vcan0 -d 0x110 -p 0F1A2B3C -c 10 -r 20\n", prog_name);
    printf("  %s -i vcan0 -m\n", prog_name);
}

/**
 * @brief Multi-ECU pattern demonstration loop.
 */
static void run_multi_demo(int sock) {
    printf(ANSI_COLOR_CYAN "[*] Running dynamic multi-ECU telemetry broadcast demo (Press Ctrl+C to stop)...\n" ANSI_COLOR_RESET);

    uint16_t rpm = 800;      /* Idle RPM */
    uint8_t  speed = 0;      /* Initial Speed km/h */
    int8_t   temp = 85;      /* Coolant Temp °C */
    uint8_t  doors = 0x00;   /* All doors locked */
    int step = 0;

    while (g_running) {
        struct can_frame frame;

        /* 1. Engine RPM (ID: 0x110, Period: ~20ms, DLC: 4) */
        rpm = 800 + (uint16_t)((step * 25) % 5500);
        uint8_t rpm_data[4] = {
            (uint8_t)(rpm >> 8),
            (uint8_t)(rpm & 0xFF),
            0x01, /* Engine Status: Running */
            0x00
        };
        can_craft_frame(&frame, CAN_ID_ENGINE_RPM, 4, rpm_data, 0, 0);
        can_send_frame(sock, &frame);
        can_print_frame(&frame, ANSI_COLOR_GREEN "[TX ENGINE]" ANSI_COLOR_RESET);
        g_frames_sent++;

        /* 2. Vehicle Speed (ID: 0x120, Period: ~50ms, DLC: 2) */
        if (step % 2 == 0) {
            speed = (uint8_t)((rpm - 800) / 70);
            uint8_t speed_data[2] = { speed, 0x00 };
            can_craft_frame(&frame, CAN_ID_VEHICLE_SPEED, 2, speed_data, 0, 0);
            can_send_frame(sock, &frame);
            can_print_frame(&frame, ANSI_COLOR_CYAN "[TX SPEED ]" ANSI_COLOR_RESET);
            g_frames_sent++;
        }

        /* 3. Body ECU: Doors & Temp (ID: 0x230, Period: ~100ms, DLC: 4) */
        if (step % 5 == 0) {
            uint8_t body_data[4] = { (uint8_t)temp, doors, 0x12, 0x34 };
            can_craft_frame(&frame, CAN_ID_BODY_DOORS, 4, body_data, 0, 0);
            can_send_frame(sock, &frame);
            can_print_frame(&frame, ANSI_COLOR_YELLOW "[TX BODY  ]" ANSI_COLOR_RESET);
            g_frames_sent++;
        }

        step++;
        sleep_ms(20);
    }
}

int main(int argc, char *argv[]) {
    const char *iface = "vcan0";
    uint32_t can_id = CAN_ID_ENGINE_RPM;
    uint8_t data[CAN_MAX_DLEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t dlc = 4;
    int custom_dlc = 0;
    uint64_t count = 1;
    long interval_ms = 100;
    int is_extended = 0;
    int is_multi_demo = 0;

    static struct option long_options[] = {
        {"iface",    required_argument, 0, 'i'},
        {"id",       required_argument, 0, 'd'},
        {"payload",  required_argument, 0, 'p'},
        {"dlc",      required_argument, 0, 'l'},
        {"count",    required_argument, 0, 'c'},
        {"rate",     required_argument, 0, 'r'},
        {"interval", required_argument, 0, 't'},
        {"extended", no_argument,       0, 'e'},
        {"multi-demo", no_argument,     0, 'm'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:d:p:l:c:r:t:emh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'd':
                can_id = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'p': {
                uint8_t parsed_dlc = 0;
                can_parse_hex_payload(optarg, data, &parsed_dlc);
                if (!custom_dlc) dlc = parsed_dlc;
                break;
            }
            case 'l':
                dlc = (uint8_t)atoi(optarg);
                custom_dlc = 1;
                break;
            case 'c':
                count = (uint64_t)strtoull(optarg, NULL, 10);
                break;
            case 'r': {
                double rate = atof(optarg);
                if (rate > 0) interval_ms = (long)(1000.0 / rate);
                break;
            }
            case 't':
                interval_ms = atol(optarg);
                break;
            case 'e':
                is_extended = 1;
                break;
            case 'm':
                is_multi_demo = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    /* Setup signal handler */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "     CAN-Sentinel: Raw C SocketCAN Broadcaster      \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf("[*] Target Interface: %s\n", iface);

    /* Open SocketCAN socket */
    int sock = can_open_socket(iface);
    if (sock < 0) {
        return 1;
    }

    printf(ANSI_COLOR_GREEN "[+] Bound successfully to %s\n" ANSI_COLOR_RESET, iface);

    uint64_t start_time = can_get_timestamp_us();

    if (is_multi_demo) {
        run_multi_demo(sock);
    } else {
        struct can_frame frame;
        can_craft_frame(&frame, can_id, dlc, data, is_extended, 0);

        printf("[*] Broadcasting ID 0x%03X (DLC: %d) every %ld ms (Count: %s)...\n",
               can_id, dlc, interval_ms, (count == 0 ? "Infinite" : argv[optind] ? argv[optind] : "1"));

        uint64_t current = 0;
        while (g_running && (count == 0 || current < count)) {
            if (can_send_frame(sock, &frame) > 0) {
                g_frames_sent++;
                can_print_frame(&frame, ANSI_COLOR_GREEN "[TX]" ANSI_COLOR_RESET);
            }

            current++;
            if (count == 0 || current < count) {
                sleep_ms(interval_ms);
            }
        }
    }

    uint64_t end_time = can_get_timestamp_us();
    double elapsed_sec = (double)(end_time - start_time) / 1000000.0;

    printf("\n" ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "[+] Broadcast complete. Frames sent: %llu in %.3f sec (%.1f fps)\n" ANSI_COLOR_RESET,
           (unsigned long long)g_frames_sent, elapsed_sec,
           elapsed_sec > 0 ? (double)g_frames_sent / elapsed_sec : 0.0);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);

#ifdef __linux__
    close(sock);
#endif
    return 0;
}
