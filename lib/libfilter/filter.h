#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include <uthash.h>

#include "scion.h"

#define FILTER_BUFSIZE 100
#define MAX_FILTER_BACKLOG 5

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
    int protocol;
} FilterKey;

typedef struct {
    FilterKey fkey;
    UT_hash_handle hh;
} Filter;

typedef struct {
    int sockfd;
    struct pollfd socket;
    Filter *filter_list;
    zlog_category_t *zc;
} FilterSocket;

FilterSocket * init_filter_socket(zlog_category_t *zc);
void poll_filter(FilterSocket *filter_socket);
int is_blocked_by_filter(FilterSocket *filter_socket, uint8_t *buf, HostAddr hop,
    uint8_t called_from_send, struct msghdr *msg);
