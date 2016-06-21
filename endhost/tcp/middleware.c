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

void *tcpmw_main_thread(void *unused) {
    struct sockaddr_un addr;
    int fd, cl;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: socket(): %s", strerror(errno));
        exit(-1);
    }

    if (mkdir(LWIP_SOCK_DIR, 0755)){
        if (errno != EEXIST){
            zlog_fatal(zc_tcp, "tcpmw_main_thread: mkdir(): %s", strerror(errno));
            exit(-1);
        }
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TCPMW_SOCKET, sizeof(addr.sun_path)-1);
    if (unlink(TCPMW_SOCKET)){
        if (errno == ENOENT)
            zlog_warn(zc_tcp, "tcpmw_main_thread: unlink(): %s", strerror(errno));
        else{
            zlog_fatal(zc_tcp, "tcpmw_main_thread: unlink(): %s", strerror(errno));
            exit(-1);
        }
    }


    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: bind(): %s", strerror(errno));
        exit(-1);
    }

    if (listen(fd, 5) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: listen(): %s", strerror(errno));
        exit(-1);
    }

    while (1) {
        if ((cl = accept(fd, NULL, NULL)) == -1) {
            err_t tmp_err = errno;
            zlog_fatal(zc_tcp, "tcpmw_main_thread: accept(): %s", strerror(errno));
            if (tmp_err == EINTR)
                continue;
            exit(-1);
        }
        /* socket() called by app. Create a netconn and a corresponding thread. */
        tcpmw_socket(cl);
    }
    return NULL;
}

void tcpmw_socket(int fd){
    char buf[TCPMW_BUFLEN];
    int pld_len;
    struct conn_args *args;
    struct netconn *conn;
    pthread_t tid;

    lwip_err = 0;
    sys_err = 0;
    if ((pld_len = tcpmw_read_cmd(fd, buf)) < 0){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket(): tcpmw_read_cmd(): %s", strerror(errno));
        goto close;
    }
    if (strncmp(buf, CMD_NEW_SOCK, CMD_SIZE) || pld_len){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket(): wrong command: %.*s", CMD_SIZE + pld_len, buf);
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
    netconn_delete(conn);
    args->conn = NULL;
close:
    close(fd);
exit:
    tcpmw_reply(args, CMD_NEW_SOCK);
}

int tcpmw_read_cmd(int fd, char *buf){
    /* Read payload length. */
    int recvd = recv_all(fd, (u8_t*)buf, PLD_SIZE);
    if (recvd < 0)
        return recvd;
    u16_t pld_len = *(u16_t *)buf;
    /* Read command and the payload. */
    recvd = recv_all(fd, (u8_t*)buf, CMD_SIZE + pld_len);
    if (recvd < 0)
        return recvd;
    if (PLD_SIZE + recvd > TCPMW_BUFLEN){
        zlog_error(zc_tcp, "tcpmw_read_cmd: incorrent command length (pld_len: %dB): %.*s",
                   pld_len, recvd, buf);
        return -1;
    }
    /* Return number of bytes after command code. */
    return pld_len;
}

void tcpmw_reply(struct conn_args *args, const char *cmd){
    u8_t buf[PLD_SIZE + RESP_SIZE];
    if (sys_err)
        lwip_err = ERR_SYS;
    *(u16_t *)buf = 0;
    memcpy(buf + PLD_SIZE, cmd, CMD_SIZE);
    buf[PLD_SIZE + RESP_SIZE - 1] = lwip_err;  /* Set error code. */
    if (send_all(args->fd, buf, PLD_SIZE + RESP_SIZE) < 0){
        zlog_fatal(zc_tcp, "tcpmw_reply(): send_all(): %s", strerror(errno));
        tcpmw_terminate(args);
    }
}

void tcpmw_terminate(struct conn_args *args){
    zlog_debug(zc_tcp, "tcpmw_terminate()");
    tcpmw_close(args);
    pthread_exit(NULL);
}

void *tcpmw_sock_thread(void *data){
    struct conn_args *args = data;
    int pld_len;
    char buf[TCPMW_BUFLEN];
    zlog_info(zc_tcp, "New sock thread started, waiting for requests");
    while ((pld_len=tcpmw_read_cmd(args->fd, buf)) >= 0) {
        if (!strncmp(buf, CMD_SEND, CMD_SIZE))
            tcpmw_send(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_RECV, CMD_SIZE) && !pld_len)
            tcpmw_recv(args);
        else if (!strncmp(buf, CMD_BIND, CMD_SIZE))
            tcpmw_bind(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_CONNECT, CMD_SIZE))
            tcpmw_connect(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_LISTEN, CMD_SIZE) && !pld_len)
            tcpmw_listen(args);
        else if (!strncmp(buf, CMD_ACCEPT, CMD_SIZE))
            tcpmw_accept(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_SET_RECV_TOUT, CMD_SIZE))
            tcpmw_set_recv_tout(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_GET_RECV_TOUT, CMD_SIZE) && !pld_len)
            tcpmw_get_recv_tout(args);
        else if (!strncmp(buf, CMD_SET_OPT, CMD_SIZE))
            tcpmw_set_sock_opt(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_GET_OPT, CMD_SIZE))
            tcpmw_get_sock_opt(args, buf + CMD_SIZE, pld_len);
        else if (!strncmp(buf, CMD_CLOSE, CMD_SIZE))
            break;
        else{
            zlog_error(zc_tcp, "tcpmw_sock_thread: command not found: %.*s (%dB)",
                       CMD_SIZE + pld_len, buf, pld_len);
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
    ip_addr_t addr;
    u16_t port, svc;
    char *p = buf;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "BIND received");
    if ((len < 5 + ADDR_NONE_LEN) || (len > 5 + ADDR_IPV6_LEN)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong command");
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
    tcpmw_reply(args, CMD_BIND);
}

void tcpmw_connect(struct conn_args *args, char *buf, int len){
    ip_addr_t addr;
    u16_t port, path_len;
    char *p = buf;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "CONN received");
    port = *((u16_t *)p);
    p += 2;  /* skip port */
    path_len = *((u16_t *)p);
    p += 2;  /* skip path_len */

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
    p += 1 + ISD_AS_LEN + get_addr_len(p[0]);
    /* TODO(PSz): don't assume IPv4 */
    path->first_hop.sin_family = AF_INET;
    memcpy(&(path->first_hop.sin_addr), p, 4);
    path->first_hop.sin_port = *(uint16_t *)(p + 4);

    if ((lwip_err = netconn_connect(args->conn, &addr, port)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_connect(): netconn_connect(): %s", lwip_strerr(lwip_err));

    tcpmw_reply(args, CMD_CONNECT);
}

void tcpmw_listen(struct conn_args *args){
    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "LIST received");
    if ((lwip_err = netconn_listen(args->conn)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_listen(): %s", lwip_strerr(lwip_err));

    tcpmw_reply(args, CMD_LISTEN);
}

void tcpmw_accept(struct conn_args *args, char *buf, int len){
    int new_fd;
    char accept_path[strlen(LWIP_SOCK_DIR) + SOCK_PATH_LEN];
    struct sockaddr_un addr;
    struct netconn *newconn;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "ACCE received");
    if (len != SOCK_PATH_LEN){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_accept(): incorrect ACCE length %.*s", len, buf);
        goto exit;
    }

    if ((lwip_err = netconn_accept(args->conn, &newconn)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_accept(): netconn_accept(): %s", lwip_strerr(lwip_err));
        goto exit;
    }
    zlog_info(zc_tcp, "tcpmw_accept(): waiting...");

    sprintf(accept_path, "%s%.*s", LWIP_SOCK_DIR, SOCK_PATH_LEN, buf);
    zlog_info(zc_tcp, "connecting to %s", accept_path);
    if ((new_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): socket(): %s", strerror(errno));
        goto exit;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, accept_path, sizeof(addr.sun_path)-1);
    if (connect(new_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): connect(%s): %s", accept_path, strerror(errno));
        goto exit;
    }

    /* Create a detached thread. */
    pthread_attr_t attr;
    pthread_t tid;
    if ((sys_err = pthread_attr_init(&attr))){
        zlog_error(zc_tcp, "tcpmw_accept(): pathread_attr_init(): %s", strerror(sys_err));
        goto exit;
    }
    if ((sys_err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))){
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_attr_setdetachstate(): %s", strerror(sys_err));
        goto exit;
    }
    struct conn_args *new_args = malloc(sizeof *new_args);
    new_args->fd = new_fd;
    new_args->conn = newconn;
    if ((sys_err = pthread_create(&tid, &attr, &tcpmw_sock_thread, new_args))){
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_create(): %s", strerror(sys_err));
        free(new_args);
        goto exit;
    }

    /* Preparing a successful response. */
    u16_t  path_len = newconn->pcb.ip->path->len;
    u8_t haddr_len = get_addr_len(newconn->pcb.ip->remote_ip.type);
    u16_t pld_len = 2 + path_len + 1 + 4 + haddr_len;
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
    memcpy(p, newconn->pcb.ip->remote_ip.addr, 4 + haddr_len);
    if (send_all(new_fd, tmp, tot_len) < 0){
        zlog_fatal(zc_tcp, "accept(): send_all(): %s", strerror(errno));
        free(tmp);
        tcpmw_terminate(args);
    }
    free(tmp);
    /* Confirm, by sending CMD_ACCEPT+ERR_OK to the "old" socket. */

exit:
    tcpmw_reply(args, CMD_ACCEPT);
}

void tcpmw_send(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    size_t tmp_sent, sent = 0;
    zlog_info(zc_tcp, "SEND received (%dB to send)", len);

    /* This is implemented more like send_all(). */
    while (sent < len){
        lwip_err = netconn_write_partly(args->conn, buf + sent, len - sent, NETCONN_COPY, &tmp_sent);
        if (lwip_err != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send(): netconn_write(): %s", lwip_strerr(lwip_err));
            zlog_debug(zc_tcp, "netconn_write(): total_sent/tmp_sent/total_len: %lu/%lu/%d",
                       sent, tmp_sent, len);
            goto exit;
        }
        sent += tmp_sent;
        zlog_debug(zc_tcp, "netconn_write(): total_sent/tmp_sent/total_len: %lu/%lu/%d",
                   sent, tmp_sent, len);
    }

exit:
    tcpmw_reply(args, CMD_SEND);
}

void tcpmw_recv(struct conn_args *args){
    u8_t *msg;
    struct netbuf *buf;
    void *data;
    u16_t len;

    lwip_err = 0;
    sys_err = 0;
    /* Receive data and put it within buf. Note that we cannot specify max_len. */
    if ((lwip_err = netconn_recv(args->conn, &buf)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_recv(): netconn_recv(): %s", lwip_strerr(lwip_err));
        goto exit;
    }

    /* Get the pointer to the data and its length. */
    if ((lwip_err = netbuf_data(buf, &data, &len)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_recv(): netbuf_data(): %s", lwip_strerr(lwip_err));
        goto exit;
    }

    msg = malloc(PLD_SIZE + RESP_SIZE);
    *(u16_t *)msg = len;
    memcpy(msg + PLD_SIZE, CMD_RECV, CMD_SIZE);
    msg[PLD_SIZE + RESP_SIZE - 1] = ERR_OK;
    if (send_all(args->fd, msg, PLD_SIZE + RESP_SIZE) < 0 || send_all(args->fd, data, len) < 0){
        zlog_fatal(zc_tcp, "tcpmw_recv(): send_all(): %s", strerror(errno));
        netbuf_delete(buf);
        free(msg);
        tcpmw_terminate(args);
    }

    netbuf_delete(buf);
    free(msg);
    return;

exit:
    tcpmw_reply(args, CMD_RECV);
}

void tcpmw_set_recv_tout(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    zlog_info(zc_tcp, "SRTO received");
    if (len != 4){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_recv_tout(): incorrect SRTO length");
        goto exit;
    }

    int timeout = (int)*(u32_t *)(buf);
    netconn_set_recvtimeout(args->conn, timeout);

exit:
    tcpmw_reply(args, CMD_SET_RECV_TOUT);
}

void tcpmw_get_recv_tout(struct conn_args *args){
    zlog_info(zc_tcp, "GRTO received");
    int timeout = netconn_get_recvtimeout(args->conn);
    u8_t *msg = malloc(PLD_SIZE + RESP_SIZE + 4);
    *(u16_t*)msg = 4;  /* Payload size */
    memcpy(msg + PLD_SIZE, CMD_GET_RECV_TOUT, CMD_SIZE);
    msg[PLD_SIZE + RESP_SIZE - 1] = ERR_OK;
    *(u32_t *)(msg + PLD_SIZE + RESP_SIZE) = (u32_t)timeout;
    if (send_all(args->fd, msg, PLD_SIZE + RESP_SIZE + 4) < 0){
        zlog_fatal(zc_tcp, "tcpmw_get_recv_tout(): send_all(): %s", strerror(errno));
        free(msg);
        tcpmw_terminate(args);
    }
    free(msg);
}

void tcpmw_set_sock_opt(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    zlog_info(zc_tcp, "SOPT received");
    if (len != 2){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_sock_opt(): incorrect SOPT length");
        goto exit;
    }

    u16_t opt = *(u16_t *)buf;
    ip_set_option(args->conn->pcb.ip, opt);

exit:
    tcpmw_reply(args, CMD_SET_OPT);
}

void tcpmw_get_sock_opt(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    zlog_info(zc_tcp, "GOPT received");
    if (len != 2){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_get_sock_opt(): incorrect GOPT length");
        goto exit;
    }

    u16_t ret, opt = *(u16_t *)buf;
    ret = ip_get_option(args->conn->pcb.ip, opt);
    u8_t *msg = malloc(PLD_SIZE + RESP_SIZE + 2);
    *(u16_t*)msg = 2;  /* Payload size */
    memcpy(msg + PLD_SIZE, CMD_GET_OPT, CMD_SIZE);
    msg[PLD_SIZE + RESP_SIZE - 1] = ERR_OK;
    *(u16_t *)(msg + PLD_SIZE + RESP_SIZE) = ret;
    if (send_all(args->fd, msg, PLD_SIZE + RESP_SIZE + 2) < 0){
        zlog_fatal(zc_tcp, "tcpmw_get_sock_opt(): send_all(): %s", strerror(errno));
        free(msg);
        tcpmw_terminate(args);
    }
    free(msg);
    return;

exit:
    tcpmw_reply(args, CMD_GET_OPT);
}

void tcpmw_close(struct conn_args *args){
    close(args->fd);
    if (args->conn){
        netconn_close(args->conn);
        netconn_delete(args->conn);
        args->conn = NULL;
    }
    free(args);
}
