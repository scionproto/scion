/*
 * Copyright 2016 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include "middleware.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
static char sock_path[UNIX_PATH_MAX];

void *tcpmw_main_thread(void *unused) {
    struct sockaddr_un addr;
    int fd, cl;
    char *env;

    tcpmw_init();  /* Init the connections array */

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: socket(): %s", strerror(errno));
        exit(-1);
    }

    errno = 0;
    if (mkdir(LWIP_SOCK_DIR, 0755)){
        if (errno != EEXIST){
            zlog_fatal(zc_tcp, "tcpmw_main_thread: mkdir(): %s", strerror(errno));
            exit(-1);
        }
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    env = getenv("DISPATCHER_ID");
    if (!env)
        env = DEFAULT_DISPATCHER_ID;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s.sock", LWIP_SOCK_DIR, env);
    strncpy(sock_path, addr.sun_path, sizeof(addr.sun_path));

    if (atexit(tcpmw_unlink_sock)){
        zlog_fatal(zc_tcp, "tcpmw_main_thread: atexit()");
        exit(-1);
    }

    errno = 0;
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: bind(): %s", strerror(errno));
        exit(-1);
    }
    zlog_info(zc_tcp, "tcpmw_main_thread: bound to %s", sock_path);

    if (listen(fd, 5) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: listen(): %s", strerror(errno));
        exit(-1);
    }

    int sys_err;
    pthread_t tid;
    if ((sys_err = pthread_create(&tid, NULL, &tcpmw_poll_loop, NULL))){
        zlog_fatal(zc_tcp, "tcpmw_main_thread(): pthread_create(): %s", strerror(sys_err));
        exit(-1);
    }

    while (1) {
        if ((cl = accept(fd, NULL, NULL)) == -1) {
            err_t tmp_err = errno;
            if (tmp_err == EINTR)
                continue;
            zlog_fatal(zc_tcp, "tcpmw_main_thread: accept(): %s", strerror(errno));
            exit(-1);
        }
        /* socket() called by app. Create a netconn and a corresponding thread. */
        tcpmw_socket(cl);
    }
    return NULL;
}

void tcpmw_init(void){
    int sys_err;
    if ((sys_err = pthread_mutex_init(&connections_lock, NULL))){
        zlog_fatal(zc_tcp, "tcpmw_init(): pthread_mutex_init(): %s", strerror(sys_err));
        exit(-1);
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++){
        tcpmw_clear_state(&connections[i], 0);
    }
}

void tcpmw_clear_state(struct conn_state *s, int free_app_buf){
    s->fd = -1;
    s->conn = NULL;
    if (free_app_buf && s->app_buf != NULL)
        free(s->app_buf);
    s->app_buf = NULL;
    s->app_buf_len = 0;
    s->app_buf_written = 0;
    s->tcp_buf = NULL;
    s->tcp_buf_len = 0;
    s->tcp_buf_written = 0;
    s->active = 0;
}

void tcpmw_unlink_sock(void){
    errno = 0;
    if (unlink(sock_path)){
        if (errno == ENOENT)
            zlog_warn(zc_tcp, "tcpmw_main_thread: unlink(): %s", strerror(errno));
        else
            zlog_fatal(zc_tcp, "tcpmw_main_thread: unlink(): %s", strerror(errno));
    }
}

void tcpmw_socket(int fd){
    char buf[TCPMW_BUFLEN];
    int pld_len;
    struct conn_args *args = NULL;
    struct netconn *conn;
    pthread_t tid;
    s8_t lwip_err = 0;

    if ((pld_len = tcpmw_read_cmd(fd, buf)) < 0){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket(): tcpmw_read_cmd(): %s", strerror(errno));
        goto close;
    }
    if (strncmp(buf, CMD_NEW_SOCK, CMD_SIZE) || pld_len){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket(): wrong command: %.*s (%dB payload)",
                   CMD_SIZE, buf, pld_len);
        goto close;
    }
    zlog_info(zc_tcp, "NEWS received");

    if ((conn = netconn_new(NETCONN_TCP)) == NULL){
        lwip_err = ERR_NEW;
        zlog_error(zc_tcp, "tcpmw_socket(): netconn_new() failed");
        goto close;
    }

    /* Create a detached thread. */
    pthread_attr_t attr;
    int sys_err;
    if ((sys_err = pthread_attr_init(&attr))){
        zlog_error(zc_tcp, "tcpmw_socket(): pathread_attr_init(): %s", strerror(sys_err));
        goto clean;
    }
    if ((sys_err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))){
        zlog_error(zc_tcp, "tcpmw_socket(): pthread_attr_setdetachstate(): %s", strerror(sys_err));
        goto clean;
    }
    args = malloc(sizeof *args);
    args->fd = fd;
    args->conn = conn;
    if ((sys_err = pthread_create(&tid, &attr, &tcpmw_sock_rpc_thread, args))){
        zlog_error(zc_tcp, "tcpmw_socket(): pthread_create(): %s", strerror(sys_err));
        free(args);
        goto clean;
    }
    goto exit;  /* OK */

clean:
    lwip_err = ERR_SYS;
    netconn_delete(conn);
close:
    close(fd);
exit:
    tcpmw_reply(args, CMD_NEW_SOCK, lwip_err);
}

int tcpmw_read_cmd(int fd, char *buf){
    /* Read payload length. */
    int recvd = recv_all(fd, (u8_t*)buf, PLD_SIZE);
    if (recvd < 0)
        return recvd;
    u16_t pld_len = *(u16_t *)buf;
    if (PLD_SIZE + CMD_SIZE + pld_len > TCPMW_BUFLEN){
        zlog_fatal(zc_tcp, "tcpmw_read_cmd(): too large payload length (%dB)", pld_len);
        return -1;
    }
    /* Read command and the payload. */
    recvd = recv_all(fd, (u8_t*)buf, CMD_SIZE + pld_len);
    if (recvd < 0)
        return recvd;
    /* Return number of bytes after command code. */
    return pld_len;
}

void tcpmw_reply(struct conn_args *args, const char *cmd, s8_t lwip_err){
    u8_t buf[PLD_SIZE + RESP_SIZE];
    *(u16_t *)buf = 0;
    memcpy(buf + PLD_SIZE, cmd, CMD_SIZE);
    buf[PLD_SIZE + RESP_SIZE - 1] = lwip_err;  /* Set error code. */
    if (send_all(args->fd, buf, PLD_SIZE + RESP_SIZE) < 0){
        zlog_fatal(zc_tcp, "tcpmw_reply(): send_all(): %s", strerror(errno));
        tcpmw_terminate(args);
    }
}

void *tcpmw_sock_rpc_thread(void *data){
    struct conn_args *args = data;
    int pld_len;
    char buf[TCPMW_BUFLEN];
    zlog_info(zc_tcp, "New sock thread started, waiting for requests");
    while ((pld_len=tcpmw_read_cmd(args->fd, buf)) >= 0) {
        char *pld_ptr = buf + CMD_SIZE;
        if (CMD_CMP(buf, CMD_BIND))
            tcpmw_bind(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_CONNECT)){
            if (tcpmw_connect(args, pld_ptr, pld_len) == ERR_OK)
                return NULL; /* Successful connect(), can quit RPC mode */
        }
        else if (CMD_CMP(buf, CMD_LISTEN))
            tcpmw_listen(args, pld_len);
        else if (CMD_CMP(buf, CMD_ACCEPT))
            tcpmw_accept(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_SET_RECV_TOUT))
            tcpmw_set_recv_tout(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_GET_RECV_TOUT))
            tcpmw_get_recv_tout(args, pld_len);
        else if (CMD_CMP(buf, CMD_SET_OPT))
            tcpmw_set_sock_opt(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_RESET_OPT))
            tcpmw_reset_sock_opt(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_GET_OPT))
            tcpmw_get_sock_opt(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_CLOSE))
            break;
        else{
            zlog_error(zc_tcp, "tcpmw_sock_rpc_thread: command not found: %.*s (%dB)",
                       CMD_SIZE, buf, pld_len);
            break;
        }
    }
    if (pld_len < 0)
        zlog_fatal(zc_tcp, "tcpmw_sock_rpc_thread: tcpmw_read_cmd(): %s", strerror(errno));
    zlog_info(zc_tcp, "tcpmw_sock_rpc_thread: leaving");
    tcpmw_close(args);
    return NULL;
}

void tcpmw_bind(struct conn_args *args, char *buf, int len){
    /* | port (2B) | svc (2B) | haddr_type (1B) | scion_addr (var) | */
    ip_addr_t addr;
    u16_t port, svc;
    char *p = buf;
    s8_t lwip_err = 0;

    zlog_info(zc_tcp, "BIND received");
    if ((len < 5 + ADDR_NONE_LEN) || (len > 5 + ADDR_IPV6_LEN)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong payload length");
        goto exit;
    }

    port = *((u16_t *)p);
    p += 2;  /* skip port */
    svc = *((u16_t *)p);
    p += 2;  /* skip SVC */
    args->conn->pcb.ip->svc = svc;  /* set svc for TCP/IP context */
    scion_addr_from_raw(&addr, p[0], p + 1);
    /* TODO(PSz): test bind with addr = NULL */
    if ((lwip_err = netconn_bind(args->conn, &addr, port)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_bind(): %s", lwip_strerr(lwip_err));
        goto exit;
    }
    char host_str[MAX_HOST_ADDR_STR];
    uint32_t isd_as = *(uint32_t*)addr.addr;
    format_host(addr.type, addr.addr, host_str, sizeof(host_str));
    zlog_info(zc_tcp, "tcpmw_bind(): bound:%d-%d, %s port %d, svc: %d",
              ISD(isd_as), AS(isd_as), host_str, port, svc);

exit:
    tcpmw_reply(args, CMD_BIND, lwip_err);
}

s8_t tcpmw_connect(struct conn_args *args, char *buf, int len){
    /* | port (2B)  | path_len (2B) | path (var) | haddr_type (1B)  | */
    /* | scion_addr (var) | first_hop_ip (4B) | first_hop_port (2B) | flags (1B) */
    ip_addr_t addr;
    u16_t port, path_len;
    char *p = buf;
    s8_t lwip_err = 0;

    if (len < 16){  /* Minimum length (with empty path and haddr) */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): incorrect payload length: %dB", len);
        goto exit;
    }

    zlog_info(zc_tcp, "CONN received");
    port = *((u16_t *)p);
    p += 2;  /* skip port */
    path_len = *((u16_t *)p);
    p += 2;  /* skip path_len */

    if (len < 16 + path_len){  /* Minimum length (with empty haddr) */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): incorrect payload length: %dB", len);
        goto exit;
    }
    if (len != 16 + path_len + get_addr_len(p[path_len])){  /* Exact length */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): incorrect payload length: %dB", len);
        goto exit;
    }

    /* Add path to the TCP/IP state */
    spath_t *path = malloc(sizeof *path);
    path->raw_path = malloc(path_len);
    memcpy(path->raw_path, p, path_len);
    path->len = path_len;
    args->conn->pcb.ip->path = path;
    zlog_info(zc_tcp, "Path added, len %d", path_len);
    p += path_len;  /* skip path */

    scion_addr_from_raw(&addr, p[0], p + 1);
    if (addr.type == ADDR_SVC_TYPE)  /* set svc for TCP/IP context */
        args->conn->pcb.ip->svc = *(u16_t*)(addr.addr + ISD_AS_LEN);
    /* Set first hop. */
    p += 1 + ISD_AS_LEN + get_addr_len(addr.type);
    /* TODO(PSz): don't assume IPv4 */
    path->first_hop.addr_type = ADDR_IPV4_TYPE;
    memcpy(path->first_hop.addr, p, 4);
    path->first_hop.port = *(uint16_t *)(p + 4);
    args->conn->pcb.ip->scion_flags = *(p + 6);

    if ((lwip_err = netconn_connect(args->conn, &addr, port)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_connect(): netconn_connect(): %s", lwip_strerr(lwip_err));

exit:
    tcpmw_reply(args, CMD_CONNECT, lwip_err);
    if (lwip_err == ERR_OK)
        tcpmw_add_connection(args);
    return lwip_err;
}

void tcpmw_listen(struct conn_args *args, int len){
    s8_t lwip_err = 0;
    zlog_info(zc_tcp, "LIST received");
    if (len){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_listen(): incorrect payload length %d", len);
        goto exit;
    }
    if ((lwip_err = netconn_listen(args->conn)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_listen(): %s", lwip_strerr(lwip_err));

exit:
    tcpmw_reply(args, CMD_LISTEN, lwip_err);
}

void tcpmw_accept(struct conn_args *args, char *buf, int len){
    /* | sock_path (SOCK_PATH_LEN B) | */
    int new_fd;
    struct sockaddr_un addr;
    struct netconn *newconn;
    s8_t lwip_err = 0;

    int sys_err = 0;
    zlog_info(zc_tcp, "ACCE received");
    if (len != SOCK_PATH_LEN){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_accept(): incorrect payload length %.*s", len, buf);
        goto exit;
    }

    if ((lwip_err = netconn_accept(args->conn, &newconn)) != ERR_OK){
        if (lwip_err == ERR_TIMEOUT)
            zlog_debug(zc_tcp, "tcpmw_accept(): netconn_accept(): %s", lwip_strerr(lwip_err));
        else
            zlog_error(zc_tcp, "tcpmw_accept(): netconn_accept(): %s", lwip_strerr(lwip_err));
        goto exit;
    }

    zlog_info(zc_tcp, "tcpmw_accept(): waiting...");

    assert(strlen(LWIP_SOCK_DIR) + SOCK_PATH_LEN < sizeof(addr.sun_path));
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s/%.*s", LWIP_SOCK_DIR, SOCK_PATH_LEN, buf);
    zlog_info(zc_tcp, "connecting to %s", addr.sun_path);
    if ((new_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): socket(): %s", strerror(errno));
        goto clean;
    }
    if (connect(new_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): connect(%s): %s", addr.sun_path, strerror(errno));
        goto clean;
    }

    /* Create a detached thread. */
    struct conn_args *new_args = malloc(sizeof *new_args);
    new_args->fd = new_fd;
    new_args->conn = newconn;

    /* Preparing a successful response. */
    u16_t  path_len = newconn->pcb.ip->path->len;
    u8_t haddr_len = get_addr_len(newconn->pcb.ip->remote_ip.type);
    /* | path_len (2B) | path (var) | haddr_type (1B)  | scion_addr (var) | */
    u16_t pld_len = 2 + path_len + 1 + ISD_AS_LEN + haddr_len;
    u16_t tot_len = PLD_SIZE + RESP_SIZE + pld_len;

    u8_t *tmp = malloc(tot_len);
    u8_t *p = tmp;
    /* First payload len */
    *(u16_t *)p = pld_len;
    p += PLD_SIZE;
    /* CMD_ACCEPT+ERR_OK */
    memcpy(p, CMD_ACCEPT, CMD_SIZE);
    p[RESP_SIZE - 1] = ERR_OK;
    p += RESP_SIZE;
    /* Encode path. */
    *((u16_t *)(p)) = path_len;
    p += 2;
    memcpy(p, newconn->pcb.ip->path->raw_path, path_len);
    p += path_len;
    /* Encode address. */
    p[0] = newconn->pcb.ip->remote_ip.type;
    p++;
    memcpy(p, newconn->pcb.ip->remote_ip.addr, ISD_AS_LEN + haddr_len);
    if (send_all(new_fd, tmp, tot_len) < 0){
        zlog_fatal(zc_tcp, "accept(): send_all(): %s", strerror(errno));
        free(tmp);
        netconn_close(newconn);
        netconn_delete(newconn);
        tcpmw_terminate(args);
    }
    free(tmp);
    /* Add new connection to the array */
    if ((sys_err = tcpmw_add_connection(new_args))){
        free(new_args);
        goto clean;
    }
    /* Confirm, by sending CMD_ACCEPT+ERR_OK to the "old" socket. */
    goto exit;

clean:
    netconn_close(newconn);
    netconn_delete(newconn);
    if (sys_err)
        lwip_err = ERR_SYS;
exit:
    tcpmw_reply(args, CMD_ACCEPT, lwip_err);
}

int tcpmw_add_connection(struct conn_args *args){
    int ret = 1;
    pthread_mutex_lock(&connections_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++){
        struct conn_state *s = &connections[i];
        if (!s->active){  /* Inactive, we can use this entry. */
            s->fd = args->fd;
            s->conn = args->conn;
            s->app_buf = malloc(TCPMW_BUFLEN);
            s->active = 1;
            zlog_debug(zc_tcp, "tcpmw_add_connection(): added %d", args->fd);
            ret = 0;
            break;
        }
    }
    pthread_mutex_unlock(&connections_lock);
    if (ret)
        zlog_error(zc_tcp, "tcpmw_add_connection(): cannot add new connection");
        // FIXME(PSz): close netconn 
    return ret;
}

void *tcpmw_poll_loop(void* dummy){
    zlog_debug(zc_tcp, "tcpmw_poll_loop() started");
    while (1){
        /* Create list of waiting fds */
        int num_fds = tcpmw_sync_conn_states();
        /* Call poll */
        zlog_debug(zc_tcp, "tcpmw_poll_loop() calling poll() with %d fds", num_fds);
        int rc = poll(pollfds, num_fds, TCP_POLLING_TOUT);
        if (rc == 0)  /* Timeout */
            continue;
        if (rc < 0) {
            zlog_fatal(zc_tcp, "tcpmw_poll_loop(): poll() error: %s", strerror(errno));
            exit(-1);
        }
        /* Iterate over results */
        struct conn_state *s;
        for (int i = 0; i < num_fds; i++){
            if (pollfds[i].revents == 0){
                zlog_debug(zc_tcp, "tcpmw_poll_loop() revents == 0: fd=%d, events %d", pollfds[i].fd, pollfds[i].events);
                continue;
            }
            /* There is an event */
            s = tcpmw_fd2state(pollfds[i].fd);
            if (s == NULL){
                zlog_error(zc_tcp, "tcpmw_poll_loop(): s == NULL");
                continue;
            }

            /* Error */
            /* if (pollfds[i].revents & ~(POLLIN|POLLOUT)){ */
            /*     tcpmw_clear_fd_state(s, 1); */
            /*     continue; */
            /* } */
            if (pollfds[i].revents & POLLIN){
                zlog_debug(zc_tcp, "tcpmw_poll_loop() POLLIN: fd=%d",pollfds[i].fd);
                tcpmw_send_to_tcp(s);
            }
            if (pollfds[i].revents & POLLOUT){
                zlog_debug(zc_tcp, "tcpmw_poll_loop() POLLOUT: fd=%d",pollfds[i].fd);
                tcpmw_send_to_app(s);
            }
        }
        /* usleep(TCP_POLLING_TOUT*1000); */
    }
    return NULL;
}

int tcpmw_sync_conn_states(void){
    int pollfd_idx = 0;

    for (int i = 0; i < MAX_CONNECTIONS; i++){
        struct conn_state *s = &connections[i];
        if (!s->active)
            continue;

        if (s->fd != -1 && s->conn != NULL){  /* Both ends are open */
            /* Ready to read smth from app */
            pollfds[pollfd_idx].fd = s->fd;
            pollfds[pollfd_idx].events = POLLIN;

            if (s->tcp_buf_len || s->conn->recv_avail)  /* Bytes to app are pending */
                pollfds[pollfd_idx].events |= POLLOUT;
            pollfd_idx++;
            continue;
        }

        if (s->fd != -1){  /* s->conn is dead, app<-tcp_buf can work. */
            if (s->tcp_buf_len){  // Bytes to app are pending
                pollfds[pollfd_idx].fd = s->fd;
                pollfds[pollfd_idx].events = POLLOUT;
                pollfd_idx++;
            }
            else  /* Can close fd as conn is dead and buf is empty */
                tcpmw_clear_fd_state(s, 1);
        }
        else if (s->conn != NULL){  /* fd is dead, only app_buf->MW can work. */
            if (s->app_buf_len)  /* Bytes from app to TCP stack. */
                tcpmw_send_to_tcp(s);
            if (!s->app_buf_len)  /* everything sent, can terminate netconn */
                tcpmw_clear_conn_state(s, 1);
        }

        if (s->fd == -1 && s->conn == NULL)  /* both are dead, can terminate the state */
            tcpmw_clear_state(s, 1);  /* free app_buf */
    }
    return pollfd_idx;
}

struct conn_state* tcpmw_fd2state(int fd){
    for (int i = 0; i < MAX_CONNECTIONS; i++){
        if (connections[i].fd == fd)
            return &connections[i];
    }
    return NULL;
}

void tcpmw_send_to_tcp(struct conn_state *s){
    zlog_debug(zc_tcp, "tcpmw_send_to_tcp() called: %d/%d", s->app_buf_written, s->app_buf_len);
    if (s->app_buf_len){ // write from the app_buf to TCP
        size_t tmp_sent, sent = s->app_buf_written;
        int to_write = s->app_buf_len - sent;
        s8_t lwip_err = 0;
        lwip_err = netconn_write_partly(s->conn, s->app_buf + sent, to_write, NETCONN_COPY|NETCONN_DONTBLOCK, &tmp_sent);
        if (lwip_err == ERR_WOULDBLOCK){
            zlog_error(zc_tcp, "tcpmw_send_to_tcp(): netconn_write_partly(): WOULDBLOCK");
            tmp_sent = 0;
        }
        else if (lwip_err != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send_to_tcp(): netconn_write(): %s %d", lwip_strerr(lwip_err), lwip_err);
            zlog_debug(zc_tcp, "netconn_write(): total_sent/tmp_sent/total_len: %zu/%zu/%d",
                       sent, tmp_sent, s->app_buf_len);
            /* Netconn is broken, close it */
            tcpmw_clear_conn_state(s, 1);
            return;
        }
        s->app_buf_written += tmp_sent;
        zlog_debug(zc_tcp, "tcpmw_send_to_tcp(): sent %d/%d/%d", (int)tmp_sent, s->app_buf_written, s->app_buf_len);
        if (s->app_buf_written == s->app_buf_len)
            tcpmw_clear_conn_state(s, 0); /* Reset app_buf metadata */
    }
    else{  /* app_buf is empty, so read from fd */
        int len = recv(s->fd, s->app_buf, TCPMW_BUFLEN, 0);
        if (len <= 0){  /* Done or error */
            if (len < 0)
                zlog_error(zc_tcp, "tcpmw_send_to_tcp(): recv(): %s", strerror(errno));
            tcpmw_clear_fd_state(s, 1);
            return;
        }
        s->app_buf_len = len;
        zlog_debug(zc_tcp, "tcpmw_send_to_tcp(): received from app %dB.", len);
        if (len)
            tcpmw_send_to_tcp(s);
    }
}

void tcpmw_send_to_app(struct conn_state *s){
    zlog_debug(zc_tcp, "tcpmw_send_to_app() called: %d/%d", s->tcp_buf_written, s->tcp_buf_len);
    if (s->tcp_buf_len){  /* write from tcp_buf to app */
        size_t sent = s->tcp_buf_written;
        int to_write = s->tcp_buf_len - sent;
        int tmp_sent = send(s->fd, s->tcp_buf + sent, to_write, 0);
        if (tmp_sent < 0){
            zlog_fatal(zc_tcp, "tcpmw_send_to_app(): send(): %s", strerror(errno));
            /* fd is broken, close it */
            tcpmw_clear_fd_state(s, 1);
            return;
        }
        s->tcp_buf_written += tmp_sent;
        zlog_debug(zc_tcp, "tcpmw_send_to_app(): sent %d/%d/%d", (int)tmp_sent, s->tcp_buf_written, s->tcp_buf_len);
        if (s->tcp_buf_written == s->tcp_buf_len)
            tcpmw_clear_fd_state(s, 0);  /* Clear only buffer */
    }
    else{  /* tcp_buf is empty, so read from netconn */
        s8_t lwip_err = 0;
        if ((lwip_err = netconn_recv(s->conn, &s->_netbuf)) != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send_to_app(): netconn_recv(): %s", lwip_strerr(lwip_err));
            tcpmw_clear_conn_state(s, 1);  //FIXME(PSz): not sure if free buf here.
            return;
        }
        /* Get the pointer to the data and its length. */
        u16_t len;
        if ((lwip_err = netbuf_data(s->_netbuf, (void **)&s->tcp_buf, &len)) != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send_to_app(): netbuf_data(): %s", lwip_strerr(lwip_err));
            tcpmw_clear_conn_state(s, 1);
            return;
        }
        s->tcp_buf_len = len;
        zlog_debug(zc_tcp, "tcpmw_send_to_app(): received from tcp %dB.", len);
        if (len)
            tcpmw_send_to_app(s);
    }
}

void tcpmw_clear_fd_state(struct conn_state *s, int terminate){
    /* Close connection */
    if (terminate && s->fd != -1){
        close(s->fd);
        s->fd = -1;
    }
    /* Nothing more can be sent to fd, free tcp_buf */
    if (s->tcp_buf != NULL){
        s->tcp_buf_written = 0;
        s->tcp_buf_len = 0;
        netbuf_delete(s->_netbuf);
        s->tcp_buf = NULL;
    }
}

void tcpmw_clear_conn_state(struct conn_state *s, int terminate){
    /* Close connection */
    if (terminate && s->conn != NULL){
        netconn_close(s->conn);
        netconn_delete(s->conn);
        s->conn = NULL;
    }
    /* Nothing more can be sent to netconn, reset buf metadata */
    if (s->app_buf != NULL){
        s->app_buf_written = 0;
        s->app_buf_len = 0;
    }
}

void tcpmw_set_recv_tout(struct conn_args *args, char *buf, int len){
    s8_t lwip_err = 0;
    zlog_info(zc_tcp, "SRTO received");
    if (len != 4){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_recv_tout(): incorrect SRTO length");
        goto exit;
    }

    int timeout = (int)*(u32_t *)(buf);
    netconn_set_recvtimeout(args->conn, timeout);

exit:
    tcpmw_reply(args, CMD_SET_RECV_TOUT, lwip_err);
}

void tcpmw_get_recv_tout(struct conn_args *args, int len){
    s8_t lwip_err = 0;
    if (len){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_get_recv_tout(): incorrect payload length %d", len);
        tcpmw_reply(args, CMD_GET_RECV_TOUT, lwip_err);
        return;
    }

    zlog_info(zc_tcp, "GRTO received");
    int timeout = netconn_get_recvtimeout(args->conn);
    u8_t msg[PLD_SIZE + RESP_SIZE + 4];
    *(u16_t*)msg = 4;  /* Payload size */
    memcpy(msg + PLD_SIZE, CMD_GET_RECV_TOUT, CMD_SIZE);
    msg[PLD_SIZE + RESP_SIZE - 1] = ERR_OK;
    *(u32_t *)(msg + PLD_SIZE + RESP_SIZE) = (u32_t)timeout;
    if (send_all(args->fd, msg, PLD_SIZE + RESP_SIZE + 4) < 0){
        zlog_fatal(zc_tcp, "tcpmw_get_recv_tout(): send_all(): %s", strerror(errno));
        tcpmw_terminate(args);
    }
}

void tcpmw_set_sock_opt(struct conn_args *args, char *buf, int len){
    s8_t lwip_err = 0;
    zlog_info(zc_tcp, "SOPT received");
    if (len != 2){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_sock_opt(): incorrect SOPT length");
        goto exit;
    }

    u16_t opt = *(u16_t *)buf;
    ip_set_option(args->conn->pcb.ip, opt);

exit:
    tcpmw_reply(args, CMD_SET_OPT, lwip_err);
}

void tcpmw_reset_sock_opt(struct conn_args *args, char *buf, int len){
    s8_t lwip_err = 0;
    zlog_info(zc_tcp, "ROPT received");
    if (len != 2){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_sock_opt(): incorrect SOPT length");
        goto exit;
    }

    u16_t opt = *(u16_t *)buf;
    ip_reset_option(args->conn->pcb.ip, opt);

exit:
    tcpmw_reply(args, CMD_RESET_OPT, lwip_err);
}

void tcpmw_get_sock_opt(struct conn_args *args, char *buf, int len){
    s8_t lwip_err = 0;
    zlog_info(zc_tcp, "GOPT received");
    if (len != 2){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_get_sock_opt(): incorrect GOPT length");
        goto exit;
    }

    u16_t ret, opt = *(u16_t *)buf;
    ret = ip_get_option(args->conn->pcb.ip, opt);
    u8_t msg[PLD_SIZE + RESP_SIZE + 2];
    *(u16_t*)msg = 2;  /* Payload size */
    memcpy(msg + PLD_SIZE, CMD_GET_OPT, CMD_SIZE);
    msg[PLD_SIZE + RESP_SIZE - 1] = ERR_OK;
    *(u16_t *)(msg + PLD_SIZE + RESP_SIZE) = ret;
    if (send_all(args->fd, msg, PLD_SIZE + RESP_SIZE + 2) < 0){
        zlog_fatal(zc_tcp, "tcpmw_get_sock_opt(): send_all(): %s", strerror(errno));
        tcpmw_terminate(args);
    }
    return;

exit:
    tcpmw_reply(args, CMD_GET_OPT, lwip_err);
}

void tcpmw_terminate(struct conn_args *args){
    tcpmw_close(args);
    pthread_exit(NULL);
}

void tcpmw_close(struct conn_args *args){
    close(args->fd);
    netconn_close(args->conn);
    netconn_delete(args->conn);
    args->conn = NULL;
    free(args);
}
