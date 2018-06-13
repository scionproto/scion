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
#include <inttypes.h>
#include "middleware.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
static char sock_path[UNIX_PATH_MAX];

void *tcpmw_main_thread(void *unused) {
    struct sockaddr_un addr;
    int fd, cl;
    char *env;

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
    if ((sys_err = pthread_create(&tid, &attr, &tcpmw_sock_thread, args))){
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

void *tcpmw_sock_thread(void *data){
    struct conn_args *args = data;
    int pld_len;
    char buf[TCPMW_BUFLEN];
    zlog_info(zc_tcp, "New sock thread started, waiting for requests");
    while ((pld_len=tcpmw_read_cmd(args->fd, buf)) >= 0) {
        char *pld_ptr = buf + CMD_SIZE;
        if (CMD_CMP(buf, CMD_BIND))
            tcpmw_bind(args, pld_ptr, pld_len);
        else if (CMD_CMP(buf, CMD_CONNECT))
            tcpmw_connect(args, pld_ptr, pld_len);
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
            zlog_error(zc_tcp, "tcpmw_sock_thread: command not found: %.*s (%dB)",
                       CMD_SIZE, buf, pld_len);
            break;
        }
    }
    if (pld_len < 0)
        zlog_fatal(zc_tcp, "tcpmw_sock_thread: tcpmw_read_cmd(): %s", strerror(errno));
    zlog_info(zc_tcp, "tcpmw_sock_thread: leaving");
    tcpmw_close(args);
    return NULL;
}

void tcpmw_bind(struct conn_args *args, char *buf, int len){
    /* | port (2B) | svc (2B) | haddr_type (1B) | scion_addr (var) | */
    ip_addr_t addr;
    u16_t port, svc;
    char *p = buf;
    s8_t lwip_err = 0;
    const int HEADER_LEN = 5;

    zlog_info(zc_tcp, "BIND received");
    if (len < HEADER_LEN) { /* Minimum length (with empty scion_addr) */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong payload length %dB", len);
        goto exit;
    }
    u8_t addr_type = buf[4];
    switch (addr_type) {
    case ADDR_IPV4_TYPE:
    case ADDR_IPV6_TYPE:
        break;
    default:
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong address type %s", addr_type_str(addr_type));
        goto exit;
    }

    port = *((u16_t *)p);
    p += 2;  /* skip port */
    svc = *((u16_t *)p);
    p += 3;  /* skip SVC and haddr_type */
    args->conn->pcb.ip->svc = svc;  /* set svc for TCP/IP context */
    int raw_addr_len = len - HEADER_LEN;
    if (scion_addr_from_raw(&addr, addr_type, p, raw_addr_len) < 0) {
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong address length %dB", raw_addr_len);
        goto exit;
    }
    /* TODO(PSz): test bind with addr = NULL */
    if ((lwip_err = netconn_bind(args->conn, &addr, port)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_bind(): %s", lwip_strerr(lwip_err));
        goto exit;
    }
    char host_str[MAX_HOST_ADDR_STR];
    isdas_t isd_as = *(isdas_t *)addr.addr;
    format_host(addr.type, addr.addr, host_str, sizeof(host_str));
    zlog_info(zc_tcp, "tcpmw_bind(): bound:%d-%" PRId64 ", %s port %d, svc: %d",
              ISD(isd_as), AS(isd_as), host_str, port, svc);

exit:
    tcpmw_reply(args, CMD_BIND, lwip_err);
}

void tcpmw_connect(struct conn_args *args, char *buf, int len){
    /* | port (2B)  | path_len (2B) | path (var) | haddr_type (1B)  | */
    /* | scion_addr (var) | first_hop_ip (4B) | first_hop_port (2B) | flags (1B) */
    ip_addr_t addr;
    u16_t port, path_len;
    char *p = buf;
    s8_t lwip_err = 0;
    const int HEADER_LEN = 12;
    u8_t addr_type;

    if (len < HEADER_LEN){  /* Minimum length (with empty path and haddr) */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): wrong payload length: %dB", len);
        goto exit;
    }
    zlog_info(zc_tcp, "CONN received");
    port = *((u16_t *)p);
    p += 2;  /* skip port */
    path_len = *((u16_t *)p);
    p += 2;  /* skip path_len */

    if (len < HEADER_LEN + path_len){  /* Minimum length (with empty haddr) */
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): wrong payload length: %dB", len);
        goto exit;
    }
    addr_type = p[path_len];
    switch (addr_type) {
    case ADDR_IPV4_TYPE:
    case ADDR_IPV6_TYPE:
    case ADDR_SVC_TYPE:
        break;
    default:
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): wrong address type %s", addr_type_str(addr_type));
        goto exit;
    }

    int raw_addr_len = len - HEADER_LEN - path_len;
    if (scion_addr_from_raw(&addr, addr_type, p + path_len + 1, raw_addr_len) < 0) {
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_connect(): wrong payload length: %dB", raw_addr_len);
        goto exit;
    }
    /* Add path to the TCP/IP state */
    spath_t *path = malloc(sizeof *path);
    path->raw_path = malloc(path_len);
    memcpy(path->raw_path, p, path_len);
    path->len = path_len;
    args->conn->pcb.ip->path = path;
    zlog_info(zc_tcp, "Path added, len %d", path_len);

    if (addr.type == ADDR_SVC_TYPE) { /* set svc for TCP/IP context */
        args->conn->pcb.ip->svc = *(u16_t*)(addr.addr + ISD_AS_LEN);
    }
    /* skip path, haddr_type and scion_addr */
    p += path_len + 1 + ISD_AS_LEN + get_addr_len(addr.type);
    /* Set first hop. */
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
        tcpmw_pipe_loop(args);
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

    /* Run netconn_accept() checking every timeout if app is stile alive */
    if ((lwip_err = tcpmw_accept_loop(args, &newconn)) != ERR_OK)
        goto exit;

    /* Connection accepted */
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
    pthread_attr_t attr;
    pthread_t tid;
    if ((sys_err = pthread_attr_init(&attr))){
        zlog_error(zc_tcp, "tcpmw_accept(): pathread_attr_init(): %s", strerror(sys_err));
        goto clean;
    }
    if ((sys_err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))){
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_attr_setdetachstate(): %s", strerror(sys_err));
        goto clean;
    }
    struct conn_args *new_args = malloc(sizeof *new_args);
    new_args->fd = new_fd;
    new_args->conn = newconn;
    if ((sys_err = pthread_create(&tid, &attr, &tcpmw_pipe_loop, new_args))){
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_create(): %s", strerror(sys_err));
        free(new_args);
        goto clean;
    }

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

s8_t tcpmw_accept_loop(struct conn_args *args, struct netconn **newconn){
    s8_t lwip_err = 0;
    /* Set temporary timeout for netconn_accept() */
    int tmp_timeout, app_timeout, org_timeout;
    tmp_timeout = app_timeout = org_timeout = netconn_get_recvtimeout(args->conn);
    if (!tmp_timeout || tmp_timeout > ACCEPT_TOUT){
        tmp_timeout = ACCEPT_TOUT;
        netconn_set_recvtimeout(args->conn, tmp_timeout);
    }
    struct pollfd app_pollfd;
    app_pollfd.fd = args->fd;
    app_pollfd.events = 0;
    while(1){
        if ((lwip_err = netconn_accept(args->conn, newconn)) == ERR_OK)
            break;

        if (lwip_err == ERR_TIMEOUT){
            /* Check whether app is alive */
            if (!poll(&app_pollfd, 1, 0)){
                /* App is alive, check timeout */
                if (!app_timeout)
                    continue;
                app_timeout -= tmp_timeout;
                if (app_timeout > 0)
                    continue;
            }
            else {
                zlog_error(zc_tcp, "tcpmw_accept(): app died: poll(): %s", strerror(errno));
                tcpmw_terminate(args);
            }
        }
        else /* Other error code than timeout */
            zlog_error(zc_tcp, "tcpmw_accept(): netconn_accept(): %s", lwip_strerr(lwip_err));
        break;
    }
    /* Set original timeout back */
    netconn_set_recvtimeout(args->conn, org_timeout);
    return lwip_err;
}

void *tcpmw_pipe_loop(void *data){
    struct conn_args *args = data;
    /* Set timeouts for receiving from app and TCP socket */
    struct timeval timeout;

    zlog_debug(zc_tcp, "Entered pipe mode");
    timeout.tv_sec = 0;
    timeout.tv_usec = TCP_POLLING_TOUT*1000;
    if (setsockopt(args->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0){
        zlog_error(zc_tcp, "tcpmw_pipe_loop(): setsockopt(): %s", strerror(errno));
        tcpmw_terminate(args);
    }
    netconn_set_recvtimeout(args->conn, TCP_POLLING_TOUT);

    /* Main loop */
    while (1){
        if (tcpmw_from_app_sock(args))
            break;
        if (tcpmw_from_tcp_sock(args))
            break;
    }

    tcpmw_terminate(args);
    return NULL;
}

int tcpmw_from_app_sock(struct conn_args *args){
    char buf[TCPMW_BUFLEN];
    s8_t lwip_err = 0;
    size_t tmp_sent, sent = 0;
    /* zlog_info(zc_tcp, "SEND received (%dB to send)", len); */
    int len = recv(args->fd, buf, TCPMW_BUFLEN, 0);
    if (len == 0)  /* Done */
        return -1;
    if (len < 0){
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT){
            zlog_debug(zc_tcp, "tcpmw_from_app_sock(): timeout");
            return 0;
        }
        else{
            zlog_error(zc_tcp, "tcpmw_from_app_sock(): recv(): %s", strerror(errno));
            return -1;
        }
    }
    zlog_debug(zc_tcp, "tcpmw_from_app_sock(): received from app %dB.", len);
    /* This is implemented more like send_all(). */
    while (sent < len){
        lwip_err = netconn_write_partly(args->conn, buf + sent, len - sent, NETCONN_COPY, &tmp_sent);
        if (lwip_err != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_from_app_sock(): netconn_write(): %s", lwip_strerr(lwip_err));
            zlog_debug(zc_tcp, "netconn_write(): total_sent/tmp_sent/total_len: %zu/%zu/%d",
                       sent, tmp_sent, len);
            return -1;
        }
        sent += tmp_sent;
        zlog_debug(zc_tcp, "netconn_write(): total_sent/tmp_sent/total_len: %zu/%zu/%d",
                   sent, tmp_sent, len);
    }
    return 0;
}

int tcpmw_from_tcp_sock(struct conn_args *args){
    struct netbuf *buf;
    void *data;
    u16_t len;
    s8_t lwip_err = 0;

    /* Receive data and put it within buf. Note that we cannot specify max_len. */
    if ((lwip_err = netconn_recv(args->conn, &buf)) != ERR_OK){
        if (lwip_err == ERR_TIMEOUT)
           return 0;
        if(lwip_err == ERR_CLSD)
            zlog_debug(zc_tcp, "tcpmw_from_tcp_sock(): netconn_recv(): %s", lwip_strerr(lwip_err));
        else
            zlog_error(zc_tcp, "tcpmw_from_tcp_sock(): netconn_recv(): %s", lwip_strerr(lwip_err));
        return -1;
    }

    /* Get the pointer to the data and its length. */
    if ((lwip_err = netbuf_data(buf, &data, &len)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_from_tcp_sock(): netbuf_data(): %s", lwip_strerr(lwip_err));
        return -1;
    }

    int ret = 0;
    if (send_all(args->fd, data, len) < 0){
        zlog_fatal(zc_tcp, "tcpmw_from_tcp_sock(): send_all(): %s", strerror(errno));
        ret = -1;
    }

    netbuf_delete(buf);
    return ret;
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
