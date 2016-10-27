/* Copyright 2015 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SCION_PROTO_CONFIGS_H
#define SCION_PROTO_CONFIGS_H

#define SSP_PROBE_INTERVAL 2000000 // us
#define SSP_PROBE_ATTEMPTS 5 // 10 seconds
#define SSP_SEND_INTERVAL 100000 // us
#define SSP_MAX_SEND_INTERVAL 3000000 // us
#define SSP_DEFAULT_SEND_WINDOW_SIZE (1 << 20)
#define SSP_DEFAULT_RECV_WINDOW_SIZE (1 << 16)
#define SSP_MAX_RTO 3000000 // us
#define SSP_MAX_RETRIES 1
#define SSP_CONNECT_ATTEMPTS 3
#define SSP_FR_THRESHOLD 3
#define SSP_MAX_LOSS_BURST 100
#define SSP_HIGH_LOSS 0.3
#define SSP_FID_LEN 8
#define SSP_FIN_THRESHOLD 3000000 // us

#define SSP_ACK 0x1
#define SSP_NEW_PATH 0x2
#define SSP_PROBE 0x4
#define SSP_WINDOW 0x8
#define SSP_CON 0x40
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
