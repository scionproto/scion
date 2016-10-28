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

#ifndef SCION_DEFINES_H
#define SCION_DEFINES_H

#include <stdint.h>
#include <stdlib.h>

#include "scion.h"

// Shared defines

typedef struct {
    uint32_t as;
    uint16_t isd;
    uint16_t interface;
} SCIONInterface;
#define IF_TOTAL_LEN 6

#define MAX_TOTAL_PATHS 20

typedef struct {
    int exists[MAX_TOTAL_PATHS];
    int receivedPackets[MAX_TOTAL_PATHS];
    int sentPackets[MAX_TOTAL_PATHS];
    int ackedPackets[MAX_TOTAL_PATHS];
    int rtts[MAX_TOTAL_PATHS];
    double lossRates[MAX_TOTAL_PATHS];
    int ifCounts[MAX_TOTAL_PATHS];
    SCIONInterface *ifLists[MAX_TOTAL_PATHS];
} SCIONStats;

#define SERIAL_INT_FIELDS 5

typedef enum {
    SCION_OPTION_BLOCKING = 0,
    SCION_OPTION_ISD_WLIST,
    SCION_OPTION_AVOID_ISD,
    SCION_OPTION_AVOID_AD,
} SCIONOptionType;

#define MAX_OPTION_LEN 20

typedef struct {
    SCIONOptionType type;
    int val;
    char data[MAX_OPTION_LEN]; // if int is not enough
    size_t len; // len of data
} SCIONOption;

#endif // SCION_DEFINES_H
