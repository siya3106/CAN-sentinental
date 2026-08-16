/**
 * @file ecu_sim.c
 * @brief Multi-ECU Telemetry Simulator in C for CAN-Sentinel.
 * Phase 1, Day 3: Multi-ECU Telemetry Simulation
 *
 * Simulates concurrent vehicle ECUs (Engine, Transmission, Brakes, Body, Climate)
 * broadcasting realistic automotive telemetry over Linux SocketCAN (vcan0)
 * at precise periodic intervals using POSIX threads.
 */

#include "can_sentinel_common.h"
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>

#ifndef _WIN32
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#endif

/* Global runtime flags and statistics */
static volatile int g_sim_running = 1;
static int g_verbose = 0;
static uint64_t g_total_frames_sent = 0;
static pthread_mutex_t g_bus_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Vehicle dynamic physical state */
typedef struct {
    double speed_kmh;      /* 0 - 220 km/h */
    double rpm;            /* 750 - 6500 RPM */
    double engine_temp_c;  /* 20 - 95 °C */
    double throttle_pct;   /* 0 - 100 % */
    double brake_pct;      /* 0 - 100 % */
    uint8_t gear;          /* 0 = Neutral/Park, 1..6 = Gears */
    uint8_t doors_locked;  /* 1 = Locked, 0 = Unlocked */
    uint8_t headlights;    /* 1 = On, 0 = Off */
    double steering_angle; /* -450.0 to +450.0 degrees */
    pthread_mutex_t state_mutex;
} vehicle_state_t;

static vehicle_state_t g_vehicle;

/* Simulation profile modes */
typedef enum {
    SIM_MODE_NORMAL_DRIVE = 0,
    SIM_MODE_IDLE,
    SIM_MODE_HIGHWAY,
    SIM_MODE_CITY
} sim_mode_t;

static sim_mode_t g_sim_mode = SIM_MODE_NORMAL_DRIVE;

/* Thread context arguments */
typedef struct {
    int sock;
    const char *iface;
} thread_args_t;

static void handle_sigint(int sig) {
    (void)sig;
    g_sim_running = 0;
}

static void precise_sleep_ms(long ms) {
    if (ms <= 0) return;
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

/**
 * @brief Thread-safe CAN frame transmitter.
 */
static int transmit_frame(int sock, const struct can_frame *frame, const char *ecu_tag, const char *color) {
    pthread_mutex_lock(&g_bus_mutex);
#ifdef __linux__
    ssize_t nbytes = write(sock, frame, sizeof(struct can_frame));
#else
    (void)sock;
    ssize_t nbytes = sizeof(struct can_frame);
#endif
    pthread_mutex_unlock(&g_bus_mutex);

    if (nbytes == sizeof(struct can_frame)) {
        pthread_mutex_lock(&g_stats_mutex);
        g_total_frames_sent++;
        pthread_mutex_unlock(&g_stats_mutex);

        if (g_verbose) {
            char prefix[64];
            snprintf(prefix, sizeof(prefix), "%s[%s]%s", color ? color : "", ecu_tag, ANSI_COLOR_RESET);
            can_print_frame(frame, prefix);
        }
        return 0;
    }
    return -1;
}

/**
 * @brief Thread 1: Vehicle Physics & Dynamic State Update Engine
 */
static void *physics_engine_thread(void *arg) {
    (void)arg;
    double time_sec = 0.0;

    while (g_sim_running) {
        pthread_mutex_lock(&g_vehicle.state_mutex);

        switch (g_sim_mode) {
            case SIM_MODE_IDLE:
                g_vehicle.throttle_pct = 0.0;
                g_vehicle.brake_pct = 0.0;
                g_vehicle.speed_kmh = 0.0;
                g_vehicle.rpm = 780.0 + 20.0 * sin(time_sec * 2.0);
                g_vehicle.gear = 0;
                break;

            case SIM_MODE_HIGHWAY:
                g_vehicle.speed_kmh = 115.0 + 10.0 * sin(time_sec * 0.1);
                g_vehicle.gear = 6;
                g_vehicle.rpm = 2200.0 + 200.0 * sin(time_sec * 0.1);
                g_vehicle.throttle_pct = 28.0;
                g_vehicle.brake_pct = 0.0;
                break;

            case SIM_MODE_CITY:
            case SIM_MODE_NORMAL_DRIVE:
            default: {
                /* Dynamic driving cycle: acceleration -> cruising -> braking */
                double cycle_t = fmod(time_sec, 60.0);

                if (cycle_t < 15.0) {
                    /* Acceleration phase */
                    double progress = cycle_t / 15.0;
                    g_vehicle.throttle_pct = 40.0 + 20.0 * sin(progress * 3.1415);
                    g_vehicle.brake_pct = 0.0;
                    g_vehicle.speed_kmh = progress * 75.0;
                    if (g_vehicle.speed_kmh < 15) g_vehicle.gear = 1;
                    else if (g_vehicle.speed_kmh < 35) g_vehicle.gear = 2;
                    else if (g_vehicle.speed_kmh < 55) g_vehicle.gear = 3;
                    else g_vehicle.gear = 4;
                    g_vehicle.rpm = 1200.0 + (g_vehicle.throttle_pct * 45.0) + (g_vehicle.speed_kmh * 20.0);
                } else if (cycle_t < 35.0) {
                    /* Cruising phase */
                    g_vehicle.throttle_pct = 20.0 + 5.0 * sin(cycle_t);
                    g_vehicle.brake_pct = 0.0;
                    g_vehicle.speed_kmh = 75.0 + 3.0 * sin(cycle_t * 0.5);
                    g_vehicle.gear = 4;
                    g_vehicle.rpm = 2100.0 + 100.0 * sin(cycle_t);
                } else if (cycle_t < 48.0) {
                    /* Braking / Deceleration phase */
                    double brake_t = (cycle_t - 35.0) / 13.0;
                    g_vehicle.throttle_pct = 0.0;
                    g_vehicle.brake_pct = 35.0 + 15.0 * sin(brake_t * 3.1415);
                    g_vehicle.speed_kmh = fmax(0.0, 75.0 * (1.0 - brake_t));
                    g_vehicle.rpm = fmax(800.0, 2100.0 * (1.0 - brake_t));
                    if (g_vehicle.speed_kmh < 10) g_vehicle.gear = 1;
                    else if (g_vehicle.speed_kmh < 30) g_vehicle.gear = 2;
                } else {
                    /* Stopped at traffic light */
                    g_vehicle.throttle_pct = 0.0;
                    g_vehicle.brake_pct = 50.0;
                    g_vehicle.speed_kmh = 0.0;
                    g_vehicle.gear = 0;
                    g_vehicle.rpm = 790.0 + 15.0 * sin(cycle_t);
                }
                break;
            }
        }

        /* Warm-up coolant temperature gradually to 90°C */
        if (g_vehicle.engine_temp_c < 90.0) {
            g_vehicle.engine_temp_c += 0.05;
        }

        /* Dynamic steering variation */
        g_vehicle.steering_angle = 15.0 * sin(time_sec * 0.3);

        pthread_mutex_unlock(&g_vehicle.state_mutex);

        time_sec += 0.05;
        precise_sleep_ms(50);
    }
    return NULL;
}

/**
 * @brief Thread 2: Engine Powertrain ECU (0x110 RPM @ 20ms, 0x120 Speed @ 50ms, 0x130 Temp @ 100ms)
 */
static void *engine_ecu_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int tick = 0;

    while (g_sim_running) {
        pthread_mutex_lock(&g_vehicle.state_mutex);
        uint16_t rpm_val = (uint16_t)g_vehicle.rpm;
        uint8_t throttle_val = (uint8_t)g_vehicle.throttle_pct;
        uint16_t speed_raw = (uint16_t)(g_vehicle.speed_kmh * 100.0); /* scale: 0.01 km/h */
        int8_t temp_val = (int8_t)g_vehicle.engine_temp_c;
        pthread_mutex_unlock(&g_vehicle.state_mutex);

        struct can_frame frame;

        /* 1. Engine RPM (0x110, Period: 20ms / 50Hz, DLC: 4) */
        uint8_t rpm_payload[4] = {
            (uint8_t)(rpm_val >> 8),
            (uint8_t)(rpm_val & 0xFF),
            throttle_val,
            0x01 /* Engine Running */
        };
        can_craft_frame(&frame, CAN_ID_ENGINE_RPM, 4, rpm_payload, 0, 0);
        transmit_frame(args->sock, &frame, "ENGINE_RPM", ANSI_COLOR_GREEN);

        /* 2. Vehicle Speed (0x120, Period: 50ms (every ~2-3 ticks), DLC: 4) */
        if (tick % 2 == 0) {
            uint8_t speed_payload[4] = {
                (uint8_t)(speed_raw >> 8),
                (uint8_t)(speed_raw & 0xFF),
                0x00, /* Odometer high */
                0x4A  /* Odometer low */
            };
            can_craft_frame(&frame, CAN_ID_VEHICLE_SPEED, 4, speed_payload, 0, 0);
            transmit_frame(args->sock, &frame, "SPEED     ", ANSI_COLOR_CYAN);
        }

        /* 3. Engine Temp & Coolant (0x130, Period: 100ms (every 5 ticks), DLC: 3) */
        if (tick % 5 == 0) {
            uint8_t temp_payload[3] = {
                (uint8_t)(temp_val + 40), /* Offset +40°C */
                0x42,                     /* Oil Pressure 4.2 bar */
                0x00                      /* Error Flags */
            };
            can_craft_frame(&frame, CAN_ID_ENGINE_TEMP, 3, temp_payload, 0, 0);
            transmit_frame(args->sock, &frame, "ENG_TEMP  ", ANSI_COLOR_BLUE);
        }

        tick++;
        precise_sleep_ms(20);
    }
    return NULL;
}

/**
 * @brief Thread 3: Transmission ECU (0x180 Gear & Torque @ 50ms)
 */
static void *transmission_ecu_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;

    while (g_sim_running) {
        pthread_mutex_lock(&g_vehicle.state_mutex);
        uint8_t current_gear = g_vehicle.gear;
        uint16_t torque_nm = (uint16_t)(g_vehicle.throttle_pct * 3.5);
        pthread_mutex_unlock(&g_vehicle.state_mutex);

        struct can_frame frame;
        uint8_t trans_payload[5] = {
            current_gear,
            (uint8_t)(torque_nm >> 8),
            (uint8_t)(torque_nm & 0xFF),
            (current_gear > 0) ? 0x01 : 0x00, /* Clutch engaged */
            0x00 /* Transmission mode: Normal Drive */
        };
        can_craft_frame(&frame, CAN_ID_TRANSMISSION, 5, trans_payload, 0, 0);
        transmit_frame(args->sock, &frame, "TRANS     ", ANSI_COLOR_MAGENTA);

        precise_sleep_ms(50);
    }
    return NULL;
}

/**
 * @brief Thread 4: Brake & ABS ECU (0x0A0 Brake Pressure & Wheel Speeds @ 10ms)
 */
static void *brake_ecu_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;

    while (g_sim_running) {
        pthread_mutex_lock(&g_vehicle.state_mutex);
        uint8_t brake_val = (uint8_t)g_vehicle.brake_pct;
        uint8_t speed_base = (uint8_t)g_vehicle.speed_kmh;
        uint8_t abs_active = (brake_val > 70 && speed_base > 40) ? 0x01 : 0x00;
        pthread_mutex_unlock(&g_vehicle.state_mutex);

        struct can_frame frame;
        uint8_t brake_payload[6] = {
            brake_val,
            abs_active,
            speed_base,       /* Wheel FL */
            speed_base,       /* Wheel FR */
            (uint8_t)(speed_base > 1 ? speed_base - 1 : 0), /* Wheel RL */
            (uint8_t)(speed_base > 1 ? speed_base - 1 : 0)  /* Wheel RR */
        };
        can_craft_frame(&frame, CAN_ID_BRAKE_OVERRIDE, 6, brake_payload, 0, 0);
        transmit_frame(args->sock, &frame, "BRAKE_ABS ", ANSI_COLOR_RED);

        precise_sleep_ms(10);
    }
    return NULL;
}

/**
 * @brief Thread 5: Body & Climate ECU (0x230 Doors @ 100ms, 0x240 Climate @ 200ms)
 */
static void *body_ecu_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int tick = 0;

    while (g_sim_running) {
        pthread_mutex_lock(&g_vehicle.state_mutex);
        uint8_t doors = g_vehicle.doors_locked;
        uint8_t lights = g_vehicle.headlights;
        pthread_mutex_unlock(&g_vehicle.state_mutex);

        struct can_frame frame;

        /* 1. Body Doors & Security (0x230, Period: 100ms / 10Hz, DLC: 4) */
        uint8_t door_payload[4] = {
            doors ? 0xFF : 0x00, /* All 4 doors locked state */
            0x00,                /* Window position (closed) */
            0x01,                /* Driver seatbelt buckled */
            0x00                 /* Alarm state */
        };
        can_craft_frame(&frame, CAN_ID_BODY_DOORS, 4, door_payload, 0, 0);
        transmit_frame(args->sock, &frame, "BODY_DOORS", ANSI_COLOR_YELLOW);

        /* 2. Interior Climate & HVAC (0x240, Period: 200ms / 5Hz, DLC: 4) */
        if (tick % 2 == 0) {
            uint8_t climate_payload[4] = {
                22,   /* Target Cabin Temp: 22°C */
                21,   /* Current Ambient Temp: 21°C */
                0x03, /* Fan Speed 3 */
                0x01  /* AC Active */
            };
            can_craft_frame(&frame, CAN_ID_BODY_CLIMATE, 4, climate_payload, 0, 0);
            transmit_frame(args->sock, &frame, "CLIMATE   ", ANSI_COLOR_CYAN);
        }

        /* 3. Lighting & Signals (0x270, Period: 100ms, DLC: 2) */
        uint8_t light_payload[2] = {
            lights ? 0x01 : 0x00, /* Low beam */
            0x00                  /* Turn signal off */
        };
        can_craft_frame(&frame, CAN_ID_LIGHTING, 2, light_payload, 0, 0);
        transmit_frame(args->sock, &frame, "LIGHTING  ", ANSI_COLOR_YELLOW);

        tick++;
        precise_sleep_ms(100);
    }
    return NULL;
}

static void print_sim_usage(const char *prog_name) {
    printf(ANSI_COLOR_BOLD "CAN-Sentinel: Multi-ECU Telemetry Simulator in C (Phase 1, Day 3)\n" ANSI_COLOR_RESET);
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --iface <name>       CAN interface to broadcast on (default: vcan0)\n");
    printf("  -m, --mode <mode>        Simulation profile: normal, idle, highway, city (default: normal)\n");
    printf("  -d, --duration <sec>     Simulation duration in seconds (0 = run indefinitely, default: 0)\n");
    printf("  -v, --verbose            Print each broadcasted frame to terminal\n");
    printf("  -h, --help               Display this help guide\n\n");
    printf("Simulated ECUs & Broadcast Rates:\n");
    printf("  - Engine ECU       : 0x110 (RPM @ 50Hz / 20ms), 0x120 (Speed @ 20Hz / 50ms), 0x130 (Temp @ 10Hz)\n");
    printf("  - Transmission ECU : 0x180 (Gear & Torque @ 20Hz / 50ms)\n");
    printf("  - Brake / ABS ECU  : 0x0A0 (Brake Pedal & Wheel Speeds @ 100Hz / 10ms)\n");
    printf("  - Body / HVAC ECU  : 0x230 (Doors @ 10Hz), 0x240 (Climate @ 5Hz), 0x270 (Lighting @ 10Hz)\n\n");
}

int main(int argc, char *argv[]) {
    const char *iface = "vcan0";
    long duration_sec = 0;

    static struct option long_options[] = {
        {"iface",    required_argument, 0, 'i'},
        {"mode",     required_argument, 0, 'm'},
        {"duration", required_argument, 0, 'd'},
        {"verbose",  no_argument,       0, 'v'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:m:d:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "idle") == 0) g_sim_mode = SIM_MODE_IDLE;
                else if (strcmp(optarg, "highway") == 0) g_sim_mode = SIM_MODE_HIGHWAY;
                else if (strcmp(optarg, "city") == 0) g_sim_mode = SIM_MODE_CITY;
                else g_sim_mode = SIM_MODE_NORMAL_DRIVE;
                break;
            case 'd':
                duration_sec = atol(optarg);
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'h':
            default:
                print_sim_usage(argv[0]);
                return (opt == 'h') ? 0 : 1;
        }
    }

    /* Initialize vehicle state */
    memset(&g_vehicle, 0, sizeof(g_vehicle));
    g_vehicle.rpm = 800.0;
    g_vehicle.engine_temp_c = 45.0;
    g_vehicle.doors_locked = 1;
    g_vehicle.headlights = 1;
    pthread_mutex_init(&g_vehicle.state_mutex, NULL);

    /* Open CAN Socket */
    int sock = can_open_socket(iface);
    if (sock < 0) {
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "   CAN-Sentinel: Multi-ECU Telemetry Simulator (C)  \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf("[*] Target Bus Interface : %s\n", iface);
    printf("[*] Driving Mode Profile : %s\n",
           g_sim_mode == SIM_MODE_IDLE ? "IDLE" :
           g_sim_mode == SIM_MODE_HIGHWAY ? "HIGHWAY" :
           g_sim_mode == SIM_MODE_CITY ? "CITY" : "NORMAL_DRIVE");
    printf("[*] Duration             : %s\n", duration_sec > 0 ? "Timed" : "Indefinite (Ctrl+C to stop)");
    printf("[*] Active Simulated ECUs: Engine (0x110, 0x120, 0x130), Trans (0x180), Brake (0x0A0), Body (0x230, 0x240, 0x270)\n");
    printf(ANSI_COLOR_GREEN "[+] Spawning concurrent ECU simulator threads...\n" ANSI_COLOR_RESET);

    thread_args_t args = { .sock = sock, .iface = iface };
    pthread_t th_physics, th_engine, th_trans, th_brake, th_body;

    uint64_t start_time = can_get_timestamp_us();

    pthread_create(&th_physics, NULL, physics_engine_thread, NULL);
    pthread_create(&th_engine, NULL, engine_ecu_thread, &args);
    pthread_create(&th_trans, NULL, transmission_ecu_thread, &args);
    pthread_create(&th_brake, NULL, brake_ecu_thread, &args);
    pthread_create(&th_body, NULL, body_ecu_thread, &args);

    long elapsed = 0;
    while (g_sim_running) {
        sleep(1);
        elapsed++;
        if (!g_verbose) {
            pthread_mutex_lock(&g_vehicle.state_mutex);
            double speed = g_vehicle.speed_kmh;
            double rpm = g_vehicle.rpm;
            uint8_t gear = g_vehicle.gear;
            pthread_mutex_unlock(&g_vehicle.state_mutex);

            pthread_mutex_lock(&g_stats_mutex);
            uint64_t total = g_total_frames_sent;
            pthread_mutex_unlock(&g_stats_mutex);

            printf("\r[*] [Telemetry Live] Speed: %5.1f km/h | RPM: %4.0f | Gear: %d | Total Frames: %6llu (Rate: %3.0f fps)",
                   speed, rpm, gear, (unsigned long long)total, elapsed > 0 ? (double)total / elapsed : 0.0);
            fflush(stdout);
        }

        if (duration_sec > 0 && elapsed >= duration_sec) {
            g_sim_running = 0;
            break;
        }
    }

    printf("\n[*] Stopping simulation threads...\n");
    pthread_join(th_physics, NULL);
    pthread_join(th_engine, NULL);
    pthread_join(th_trans, NULL);
    pthread_join(th_brake, NULL);
    pthread_join(th_body, NULL);

    uint64_t end_time = can_get_timestamp_us();
    double total_sec = (double)(end_time - start_time) / 1000000.0;

    printf("\n" ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "[+] Multi-ECU Simulation Finished Successfully\n" ANSI_COLOR_RESET);
    printf("    Total Frames Broadcast : %llu\n", (unsigned long long)g_total_frames_sent);
    printf("    Elapsed Time           : %.2f seconds\n", total_sec);
    printf("    Average Bus Throughput : %.1f frames/sec\n", total_sec > 0 ? (double)g_total_frames_sent / total_sec : 0.0);
    printf(ANSI_COLOR_BLUE "====================================================\n" ANSI_COLOR_RESET);

#ifdef __linux__
    close(sock);
#endif
    return 0;
}
