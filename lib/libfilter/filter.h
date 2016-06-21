#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include <uthash.h>

#include "scion.h"

#define FILTER_BUFSIZE 100
#define MAX_FILTER_BACKLOG 5
#define FILTER_LEVELS 4  // Levels are: 0 = * < ISD_AS < IP < Port = 3

#define BLOCK_INGRESS 0
#define BLOCK_EGRESS 1
#define BLOCK_HOP_BY_HOP 0
#define BLOCK_END2END 1

typedef struct {
    SCIONAddr src;
    SCIONAddr dst;
    SCIONAddr hop;
    uint8_t on_egress;
    uint8_t is_end2end;
    uint8_t l4_proto;
} FilterKey;

typedef struct {
    FilterKey fkey;
    UT_hash_handle hh;
} Filter;

typedef struct {
    int sock;
    struct pollfd pollfd;
    Filter *filter_list[FILTER_LEVELS][FILTER_LEVELS][FILTER_LEVELS][L4_PROTOCOL_COUNT];
    zlog_category_t *zc;
} FilterSocket;

FilterSocket * init_filter_socket(zlog_category_t *zc);
void close_filter_socket(FilterSocket *filter_socket);
void poll_filter(FilterSocket *filter_socket);
int is_blocked_by_filter(FilterSocket *filter_socket, uint8_t *buf, HostAddr hop,
    uint8_t called_from_send, struct msghdr *msg);
void populate_test_filter_hashmaps(FilterSocket *filter_socket);
