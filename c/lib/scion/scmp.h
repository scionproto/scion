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

#define MAX_SCMP_CLASS_TYPE_STR 50

#define foreach_scmp_class                        \
_(GENERAL, "GENERAL")                             \
_(ROUTING, "ROUTING")                             \
_(CMNHDR, "CMNHDR")                               \
_(PATH, "PATH")                                   \
_(EXT, "EXT")

typedef enum {
#define _(sym, str) SCMP_CLASS_##sym,
    foreach_scmp_class
#undef _
    SCMP_CLASS_N
} SCMPClass;

#define foreach_scmp_general                      \
_(UNSPECIFIED, "UNSPECIFIED")                     \
_(ECHO_REQUEST, "ECHO_REQUEST")                   \
_(ECHO_REPLY, "ECHO_REPLY")                       \
_(TRACEROUTE_REQUEST, "TRACEROUTE_REQUEST")       \
_(TRACEROUTE_REPLY, "TRACEROUTE_REPLY")           \
_(RECORDPATH_REQUEST, "RECORDPATH_REQUEST")       \
_(RECORDPATH_REPLY, "RECORDPATH_REPLY")

typedef enum {
#define _(sym, str) SCMP_##sym,
    foreach_scmp_general
#undef _
    SCMP_GENERAL_N
} SCMPGeneralType;

#define foreach_scmp_routing                      \
_(UNREACH_NET, "UNREACH_NET")                     \
_(UNREACH_HOST, "UNREACH_HOST")                   \
_(L2_ERROR, "L2_ERROR")                           \
_(UNREACH_PROTO, "UNREACH_PROTO")                 \
_(UNREACH_PORT, "UNREACH_PORT")                   \
_(UNKNOWN_HOST, "UNKNOWN_HOST")                   \
_(BAD_HOST, "BAD_HOST")                           \
_(OVERSIZE_PKT, "OVERSIZE_PKT")                   \
_(ADMIN_DENIED, "ADMIN_DENIED")

typedef enum {
#define _(sym, str) SCMP_##sym,
    foreach_scmp_routing
#undef _
    SCMP_ROUTING_N
} SCMPRoutingType;

#define foreach_scmp_cmnhdr                       \
_(BAD_VERSION, "BAD_VERSION")                     \
_(BAD_DST_TYPE, "BAD_DST_TYPE")                   \
_(BAD_SRC_TYPE, "BAD_SRC_TYPE")                   \
_(BAD_PKT_LEN, "BAD_PKT_LEN")                     \
_(BAD_IOF_OFFSET, "BAD_IOF_OFFSET")               \
_(BAD_HOF_OFFSET, "BAD_HOF_OFFSET")

typedef enum {
#define _(sym, str) SCMP_##sym,
    foreach_scmp_cmnhdr
#undef _
    SCMP_CMNHDR_N
} SCMPCmnHdrType;

#define foreach_scmp_path                         \
_(PATH_REQUIRED, "PATH_REQUIRED")                 \
_(BAD_MAC, "BAD_MAC")                             \
_(EXPIRED_HOF, "EXPIRED_HOF")                     \
_(BAD_IF, "BAD_IF")                               \
_(REVOKED_IF, "REVOKED_IF")                       \
_(NON_ROUTING_HOF, "NON_ROUTING_HOF")             \
_(DELIVERY_FWD_ONLY, "DELIVERY_FWD_ONLY")         \
_(DELIVERY_NON_LOCAL, "DELIVERY_NON_LOCAL")

typedef enum {
#define _(sym, str) SCMP_##sym,
    foreach_scmp_path
#undef _
    SCMP_PATH_N
} SCMPPathType;

#define foreach_scmp_ext                          \
_(TOO_MANY_HOPBYHOP, "TOO_MANY_HOPBYHOP")         \
_(BAD_EXT_ORDER, "BAD_EXT_ORDER")                 \
_(BAD_HOPBYHOP, "BAD_HOPBYHOP")                   \
_(BAD_END2END, "BAD_END2END")                     \

typedef enum {
#define _(sym, str) SCMP_##sym,
    foreach_scmp_ext
#undef _
    SCMP_EXT_N
} SCMPExtType;

uint16_t scmp_checksum(uint8_t *buf);
void update_scmp_checksum(uint8_t *buf);
SCMPPayload *scmp_parse_payload(SCMPL4Header *scmp_hdr);

const char *scmp_class_to_str(uint16_t index);
const char *scmp_general_to_str(uint16_t index);
const char *scmp_routing_to_str(uint16_t index);
const char *scmp_cmnhdr_to_str(uint16_t index);
const char *scmp_path_to_str(uint16_t index);
const char *scmp_ext_to_str(uint16_t index);
const char *scmp_ct_to_str(char *buf, uint16_t class, uint16_t type);

#endif
