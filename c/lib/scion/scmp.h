#ifndef _SCMP_H_
#define _SCMP_H_

#pragma pack(push)
#pragma pack(1)

typedef struct {
    uint16_t class_;
    uint16_t type;
    uint16_t len;
    uint16_t checksum;
    uint64_t timestamp;
} SCMPL4Header;

typedef struct {
    uint8_t info_len;
    uint8_t cmnhdr_len;
    uint8_t addr_len;
    uint8_t path_len;
    uint8_t exts_len;
    uint8_t l4_len;
    uint8_t l4_proto;
    uint8_t _padding;
} SCMPMetaHeader;

#pragma pack(pop)

typedef struct {
    SCMPMetaHeader *meta;
    void *info;
    SCIONCommonHeader *cmnhdr;
    void *addr;
    void *path;
    void *exts;
    void *l4hdr;
} SCMPPayload;

typedef enum {
    SCMP_GENERAL_CLASS,
    SCMP_ROUTING_CLASS,
    SCMP_CMNHDR_CLASS,
    SCMP_PATH_CLASS,
    SCMP_EXT_CLASS,
} SCMPClass;

typedef enum {
    SCMP_UNSPECIFIED,
    SCMP_ECHO_REQUEST,
    SCMP_ECHO_REPLY,
} SCMPGeneralType;

typedef enum {
    SCMP_UNREACH_NET,
    SCMP_UNREACH_HOST,
    SCMP_L2_ERROR,
    SCMP_UNREACH_PROTO,
    SCMP_UNREACH_PORT,
    SCMP_UNKNOWN_HOST,
    SCMP_BAD_HOST,
    SCMP_OVERSIZE_PKT,
    SCMP_ADMIN_DENIED,
} SCMPRoutingType;

typedef enum {
    SCMP_BAD_VERSION,
    SCMP_BAD_DST_TYPE,
    SCMP_BAD_SRC_TYPE,
    SCMP_BAD_PKT_LEN,
    SCMP_BAD_IOF_OFFSET,
    SCMP_BAD_HOF_OFFSET,
} SCMPCmnHdrType;

typedef enum {
    SCMP_PATH_REQUIRED,
    SCMP_BAD_MAC,
    SCMP_EXPIRED_HOF,
    SCMP_BAD_IF,
    SCMP_REVOKED_IF,
    SCMP_NON_ROUTING_HOF,
    SCMP_DELIVERY_FWD_ONLY,
    SCMP_DELIVERY_NON_LOCAL,
} SCMPPathType;

typedef enum {
    SCMP_TOO_MANY_HOPBYHOP,
    SCMP_BAD_EXT_ORDER,
    SCMP_BAD_HOPBYHOP,
    SCMP_BAD_END2END,
} SCMPExtType;

uint16_t scmp_checksum(uint8_t *buf);
void update_scmp_checksum(uint8_t *buf);
SCMPPayload *scmp_parse_payload(SCMPL4Header *scmp_hdr);

#endif
