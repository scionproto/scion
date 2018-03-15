#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/* Host addr lengths by type */
const int ADDR_LENS[] = {0, 4, 16, 2};

/*
 * Get addr length by type
 * type: Address type
 * return value: Length of address of given type
 */
int get_addr_len(int type)
{
    return ADDR_LENS[type];
}

/*
 * Get dst ISD_AS
 * buf: Pointer to start of SCION packet
 * return value: dst ISD_AS value
 */
isdas_t get_dst_isd_as(uint8_t *buf)
{
    return be64toh(*(isdas_t *)(buf + DST_IA_OFFSET));
}

/*
 * Get src ISD_AS
 * buf: Pointer to start of SCION packet
 * return value: src ISD_AS value
 */
isdas_t get_src_isd_as(uint8_t *buf)
{
    return be64toh(*(isdas_t *)(buf + SRC_IA_OFFSET));
}

/*
 * Get length of dst host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of dst host addr
 * */
uint8_t get_dst_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[DST_TYPE(sch)];
}

/*
 * Get length of src host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of src host addr
 * */
uint8_t get_src_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[SRC_TYPE(sch)];
}

/*
 * Get combined length of dst and src addresses
 * buf: Pointer to start of SCION packet
 * return value: Length of dst + src addresses
 * */
uint8_t get_addrs_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ISD_AS_LEN * 2 + ADDR_LENS[DST_TYPE(sch)] + ADDR_LENS[SRC_TYPE(sch)];
}

/*
 * Get dst host addr
 * buf: Pointer to start of SCION packet
 * return value: pointer to start of dst host addr
 * */
uint8_t * get_dst_addr(uint8_t *buf)
{
    int offset = sizeof(SCIONCommonHeader) + ISD_AS_LEN * 2;
    return (uint8_t *)(buf + offset);
}

/*
 * Get src host addr
 * buf: Pointer to start of SCION packet
 * return value: pointer to start of src host addr
 * */
uint8_t * get_src_addr(uint8_t *buf)
{
    int offset = sizeof(SCIONCommonHeader) + ISD_AS_LEN * 2 + get_dst_len(buf);
    return (uint8_t *)(buf + offset);
}

/*
 * Get short description of address type.
 * Returns "UNKOWN" if the address type isn't supported.
 * return type: char pointer to description string.
 */
char *addr_type_str(int addr_type) {
    switch (addr_type) {
        case ADDR_IPV4_TYPE:
            return "IPv4";
        case ADDR_IPV6_TYPE:
            return "IPv6";
        case ADDR_SVC_TYPE:
            return "SVC";
        default:
            return "UNKNOWN";
    }
}

/*
 * Format host address as string into the supplied buffer. If the address type
 * isn't supported, "UNKNOWN" is written to the buffer instead. Supports
 * ipv4/ipv6/SVC.
 * addr_type: address type.
 * addr: pointer to first byte of address.
 * buf: char array to write the result to.
 * size: size of supplied char array.
 */
void format_host(int addr_type, uint8_t *addr, char *buf, int size) {
    int af;
    switch(addr_type) {
        case ADDR_IPV4_TYPE:
            af = AF_INET;
            break;
        case ADDR_IPV6_TYPE:
            af = AF_INET6;
            break;
        case ADDR_SVC_TYPE:
            snprintf(buf, size, "%d", ntohs(*(uint16_t *)addr));
            return;
        default:
            snprintf(buf, size, "UNKNOWN");
            return;
    }
    inet_ntop(af, (void *)addr, buf, size);
}

/*
 * Print address header to stderr
 * buf: Pointer to start of packet.
 */
void print_addresses(uint8_t *buf) {
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    isdas_t dst_isd_as = get_dst_isd_as(buf);
    isdas_t src_isd_as = get_src_isd_as(buf);
    char host_str[MAX_HOST_ADDR_STR];
    format_host(DST_TYPE(sch), get_dst_addr(buf), host_str, sizeof(host_str));
    fprintf(stderr, "Dst: ISD-AS: %d-%" PRId64 " Host(%s): %s\n", ISD(dst_isd_as),
            AS(dst_isd_as), addr_type_str(DST_TYPE(sch)), host_str);
    format_host(SRC_TYPE(sch), get_src_addr(buf), host_str, sizeof(host_str));
    fprintf(stderr, "Src: ISD-AS: %d-%" PRId64 " Host(%s): %s\n", ISD(src_isd_as),
            AS(src_isd_as), addr_type_str(SRC_TYPE(sch)), host_str);
}
