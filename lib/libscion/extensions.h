#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_
#include "packet.h"

// Extensions
#define SCION_EXT_LINE LINE_LEN
#define SCION_EXT_SUBHDR 3

#define HOP_BY_HOP 0
#define END_TO_END 222

// Hop by hop
#define TRACEROUTE 0
#define SIBRA 1
#define SCMP 2
#define ONE_HOP_PATH 3

// End to end
#define PATH_TRANSPORT 0
#define PATH_PROBE 1

// Max number of supported HopByHop extensions (does not include SCMP)
#define MAX_HOPBYHOP_EXT 3

#define TRACEROUTE_HOP_LEN 8
// Payload length of one hop path extension.
#define ONE_HOP_PATH_PLDLEN 5

uint8_t * find_extension(uint8_t *buf, uint8_t ext_class, uint8_t ext_type);
int get_total_ext_len(uint8_t *buf);
void build_one_hop_path_ext(seh_t *ext);

#endif
