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

#define getProbeNum(ext) (*(uint32_t *)((uint8_t *)ext->data + 1))
#define setProbeNum(ext, num) (*(uint32_t *)((uint8_t *)ext->data + 1) = htonl(num))
#define getHeaderLen(ext) ((ext->headerLen + 1) * SCION_EXT_LINE)
#define isProbeAck(ext) (*(uint8_t *)((ext)->data))

#endif
