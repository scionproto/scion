#ifndef _PATH_H_
#define _PATH_H_

#include "defines.h"

// 12bit is egress if and 8 bit gap between uint32 and 24bit field
#define INGRESS_IF(HOF) (ntohl((HOF)->ingress_egress_if) >> (12 + 8))
#define EGRESS_IF(HOF) ((ntohl((HOF)->ingress_egress_if) >> 8) & 0x000fff)

int reverse_path(uint8_t *buf, uint8_t *reverse);
uint8_t * get_hof_ver(uint8_t *buf, int ingress);
uint8_t * get_hof_ver_normal(uint8_t *buf);

#endif
