#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include "scion.h"

#define FILTER_BUFSIZE 10000
#define FILTER_CMD_SIZE (3 * sizeof(SCIONAddr) + 2)
#define MAX_FILTER_BACKLOG 5
#define FILTER_LEVELS 5  // Levels are: 0 = * < ISD < AS < IP < Port = 4

#define ON_EGRESS(x) (((x) >> 4) & 1)
#define IS_SRC_NEGATED(x) (((x) >> 3) & 1)
#define IS_DST_NEGATED(x) (((x) >> 2) & 1)
#define IS_HOP_NEGATED(x) (((x) >> 1) & 1)
#define IS_FILTER_NEGATED(x) ((x) & 1)

#define INGRESS 0
#define EGRESS 1

typedef struct {
    SCIONAddr src;
    SCIONAddr dst;
    SCIONAddr hop;
    uint8_t options;
} Filter;

typedef struct {
    int sock;
    int conn_sock;
    struct pollfd pollfd;
    Filter *filter_list[L4_PROTOCOL_COUNT];
    uint8_t num_filters_for_l4[L4_PROTOCOL_COUNT];
} FilterSocket;

FilterSocket * init_filter_socket(zlog_category_t *zc_t);
void close_filter_socket(FilterSocket *fs);
void poll_filter(FilterSocket *fs);
int is_blocked_by_filter(FilterSocket *fs, uint8_t *buf, HostAddr *hop, int on_egress);
