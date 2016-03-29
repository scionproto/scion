#ifndef SCION_PROTO_CONFIGS_H
#define SCION_PROTO_CONFIGS_H

#define SSP_PROBE_INTERVAL 500000 // us
#define SSP_PROBE_ATTEMPTS (2 * 20)
#define SSP_SEND_INTERVAL 100000 // us
#define SSP_MAX_SEND_INTERVAL 3000000 // us
#define SSP_DEFAULT_WINDOW_SIZE (1 << 16)
#define SSP_MAX_RTO 3000000 // us
#define SSP_MAX_RETRIES 1
#define SSP_CONNECT_ATTEMPTS 3
#define SSP_FR_THRESHOLD 3
#define SSP_MAX_LOSS_BURST 100
#define SSP_HIGH_LOSS 0.3
#define SSP_FID_LEN 8

#define SSP_ACK 0x1
#define SSP_NEW_PATH 0x2
#define SSP_PROBE 0x4
#define SSP_WINDOW 0x8
#define SSP_FULL 0x10
#define SSP_FIN 0x80

typedef enum {
    SCION_CLOSED = 0,
    SCION_SHUTDOWN,
    SCION_FIN_RCVD,
    SCION_FIN_READ,
    SCION_RUNNING
} SCIONState;

// SUDP protocol

#define SUDP_PROBE_INTERVAL 1000000
#define SUDP_RECV_BUFFER (1 << 16)
#define SUDP_PROBE_WINDOW 3

#define SUDP_PROBE 0x1
#define SUDP_PROBE_ACK 0x2

#endif
