#ifndef SCION_GENERAL_CONFIG_H
#define SCION_GENERAL_CONFIG_H

// Build config

//#define SIMULATOR // uncomment for WANem testing

#define DEBUG_MODE 0
#if DEBUG_MODE
#define DEBUG printf
#else
#define DEBUG(...)
#endif

#define MAX_PATH_LEN 512
#define MAX_USED_PATHS 2
#define MAX_DATA_PACKET 2048

#define SCION_DEFAULT_MTU 1500

// time values in us
#define SCION_TIMER_INTERVAL 50000
#define SCION_DEFAULT_RTO 3000000
#define SCION_DEFAULT_RTT 300000

#endif
