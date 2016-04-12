#ifndef _EXTENSIONS_H_
#define _EXTENSIONS_H_

// Extensions
#define SCION_EXT_LINE 8
#define SCION_EXT_SUBHDR 3

#define HOP_BY_HOP 0
#define END_TO_END 222

#define TRACEROUTE 0
#define SIBRA 1

#define PATH_TRANSPORT 0
#define PATH_PROBE 1

uint8_t * find_extension(void *buf, uint8_t ext_class, uint8_t ext_type);
int get_total_ext_len(void *buf);

#endif
