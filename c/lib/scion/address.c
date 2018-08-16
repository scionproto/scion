#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "scion.h"

/*
 * Get addr length by type
 * type: Address type
 * return value: Length of address of given type
 *   0 if NONE or invalid type
 */
int get_addr_len(uint8_t type)
{
    if (type < ADDR_TYPE_N) {
        return ADDR_LENS[type];
    }
    return 0;
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
 *   0 if NONE or invalid type
 * */
uint8_t get_dst_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return get_addr_len(DST_TYPE(sch));
}

/*
 * Get length of src host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of src host addr
 *   0 if NONE or invalid type
 * */
uint8_t get_src_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return get_addr_len(SRC_TYPE(sch));
}

/*
 * Get combined length of dst and src addresses
 * buf: Pointer to start of SCION packet
 * return value: Length of dst + src addresses
 * */
uint8_t get_addrs_len(uint8_t *buf)
{
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ISD_AS_LEN * 2 + get_addr_len(DST_TYPE(sch)) + get_addr_len(SRC_TYPE(sch));
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
char *addr_type_str(uint8_t addr_type) {
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

char *format_isd_as(char *str, uint32_t size, isdas_t isd_as) {
    isdas_t as = AS(isd_as);
    if ((as >> 32) == 0) {
        // BGP number - lower 32 bits
        snprintf(str, size, "%hu-%u", ISD(isd_as), (uint32_t)as);
    } else {
        snprintf(str, size, "%hu-%hx:%hx:%hx", ISD(isd_as),
                (uint16_t)(as >> 32), (uint16_t)(as >> 16), (uint16_t)as);
    }
    return str;
}

char *format_as(char *str, uint32_t size, isdas_t isd_as) {
    isdas_t as = AS(isd_as);
    if ((as >> 32) == 0) {
        // BGP number - lower 32 bits
        snprintf(str, size, "%u", (uint32_t)as);
    } else {
        snprintf(str, size, "%hx:%hx:%hx",
                (uint16_t)(as >> 32), (uint16_t)(as >> 16), (uint16_t)as);
    }
    return str;
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
    char isd_as_str[MAX_ISD_AS_STR];

    format_host(DST_TYPE(sch), get_dst_addr(buf), host_str, sizeof(host_str));
    format_isd_as(isd_as_str, MAX_ISD_AS_STR, dst_isd_as);
    fprintf(stderr, "Dst: ISD-AS: %s Host(%s): %s\n", isd_as_str,
            addr_type_str(DST_TYPE(sch)), host_str);

    format_host(SRC_TYPE(sch), get_src_addr(buf), host_str, sizeof(host_str));
    format_isd_as(isd_as_str, MAX_ISD_AS_STR, src_isd_as);
    fprintf(stderr, "Src: ISD-AS: %s Host(%s): %s\n", isd_as_str,
            addr_type_str(SRC_TYPE(sch)), host_str);
}
