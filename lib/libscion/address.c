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
 * Get src ISD_AS
 * buf: Pointer to start of SCION packet
 * return value: src ISD_AS value, 0 on error
 */
uint32_t get_src_isd_as(void *buf)
{
    return ntohl(*(uint32_t *)(buf + sizeof(SCIONCommonHeader)));
}

/* 
 * Get src host addr
 * buf: Pointer to start of SCION packet
 * return value: pointer to start of src host addr, NULL on error
 * */
uint8_t * get_src_addr(void *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return (uint8_t *)(sch + 1) + ISD_AS_LEN;
}

/* 
 * Get length of src host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of src host addr, 0 on error
 * */
uint8_t get_src_len(void *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[SRC_TYPE(sch)];
}

/*
 * Get dst ISD_AS
 * buf: Pointer to start of SCION packet
 * return value: dst ISD_AS value, 0 on error
 */
uint32_t get_dst_isd_as(void *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;

    uint8_t src_len;
    uint8_t src_type = SRC_TYPE(sch);

    if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE) {
        printf("invalid src addr type: %d\n", src_type);
        return 0;
    }

    src_len = ADDR_LENS[src_type];
    return ntohl(*(uint32_t *)(buf + sizeof(SCIONCommonHeader) + ISD_AS_LEN + src_len));
}

/* 
 * Get dst host addr
 * buf: Pointer to start of SCION packet
 * return value: Pointer to start of dst host addr, NULL on error
 * */
uint8_t * get_dst_addr(void *buf)
{
    if (!buf)
        return NULL;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint8_t src_len;
    uint8_t src_type = SRC_TYPE(sch);

    if (src_type < ADDR_NONE_TYPE || src_type > ADDR_SVC_TYPE) {
        printf("invalid src addr type: %d\n", src_type);
        return NULL;
    }

    src_len = ADDR_LENS[src_type];
    void *ret = (uint8_t *)(sch + 1) + ISD_AS_LEN +
        src_len + ISD_AS_LEN;
    return ret;
}

/* 
 * Get length of dst host addr
 * buf: Pointer to start of SCION packet
 * return value: Length of dst host addr, 0 on error
 * */
uint8_t get_dst_len(void *buf)
{
    if (!buf)
        return 0;

    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    return ADDR_LENS[DST_TYPE(sch)];
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
void print_addresses(void *buf) {
    if (!buf)
        return;
    SCIONCommonHeader *sch = (SCIONCommonHeader *)buf;
    uint32_t src_isd_as = get_src_isd_as(buf);
    uint32_t dst_isd_as = get_dst_isd_as(buf);
    char host_str[MAX_HOST_ADDR_STR];
    format_host(SRC_TYPE(sch), get_src_addr(buf), host_str, sizeof(host_str));
    fprintf(stderr, "Src: ISD-AS: %d-%d Host(%s): %s\n", ISD(src_isd_as),
            AS(src_isd_as), addr_type_str(SRC_TYPE(sch)), host_str);
    format_host(DST_TYPE(sch), get_dst_addr(buf), host_str, sizeof(host_str));
    fprintf(stderr, "Dst: ISD-AS: %d-%d Host(%s): %s\n", ISD(dst_isd_as),
            AS(dst_isd_as), addr_type_str(DST_TYPE(sch)), host_str);
}
