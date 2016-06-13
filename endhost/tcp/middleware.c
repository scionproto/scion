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

void *tcpmw_main_thread(void) {
    struct sockaddr_un addr;
    int fd, cl;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: socket() failed");
        exit(-1);
    }

    mkdir(LWIP_SOCK_DIR, 0755);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, RPCD_SOCKET, sizeof(addr.sun_path)-1);
    unlink(RPCD_SOCKET);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: bind() failed");
        exit(-1);
    }

    if (listen(fd, 5) == -1) {
        zlog_fatal(zc_tcp, "tcpmw_main_thread: listen() failed");
        exit(-1);
    }

    while (1) {
        if ((cl = accept(fd, NULL, NULL)) == -1) {
            zlog_fatal(zc_tcp, "tcpmw_main_thread: accept() failed");
            continue;
        }
        /* socket() called by app. Create a netconn and a corresponding thread. */
        tcpmw_socket(cl);
    }
    return 0;
}

void tcpmw_socket(int fd){
    char buf[8];
    struct conn_args *args;
    struct netconn *conn;
    pthread_t tid;

    lwip_err = 0;
    sys_err = 0;
    if (read(fd, buf, sizeof(buf)) != CMD_SIZE){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_socket() error on read");
        goto fail;
    }
    if (strncmp(buf, CMD_NEW_SOCK, CMD_SIZE)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket() wrong command");
        goto fail;
    }
    zlog_info(zc_tcp, "NEWS received");

    if ((conn = netconn_new(NETCONN_TCP)) == NULL){
        lwip_err = ERR_NEW;
        zlog_error(zc_tcp, "tcpmw_socket(): netconn_new() failed");
        goto fail;
    }

    /* Create a detached thread. */
    pthread_attr_t attr;
    if (pthread_attr_init(&attr)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_socket(): attribute init failed");
        goto fail;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_socket(): setting detached state failed");
        goto fail;
    }
    args = malloc(sizeof *args);
    args->fd = fd;
    args->conn = conn;
    if (pthread_create(&tid, &attr, &tcpmw_sock_thread, args)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_create() failed");
        free(args);
        goto fail;
    }
    goto reply;  /* OK */

fail:
    close(fd);
reply:
    tcpmw_reply(fd, CMD_NEW_SOCK);
}

void tcpmw_reply(int fd, const char *cmd){
    char buf[RESP_SIZE];
    if (lwip_err){
        if (lwip_err == ERR_MW)
            zlog_debug(zc_tcp, "API/TCP middleware error.");
        else if (lwip_err == ERR_NEW)
            zlog_debug(zc_tcp, "netconn_new() error.");
        else if (lwip_err == ERR_SYS)
            zlog_debug(zc_tcp, "System's call error.");
        else
            zlog_debug(zc_tcp, "%s", lwip_strerr(lwip_err));
    }
    if (sys_err){
        zlog_debug(zc_tcp, "%s", strerror(sys_err));
        lwip_err = ERR_SYS;
    }
    memcpy(buf, cmd, RESP_SIZE - 1);
    buf[RESP_SIZE - 1] = lwip_err;  /* Set error code. */
    write(fd, buf, RESP_SIZE);
}

void *tcpmw_sock_thread(void *data){
    struct conn_args *args = data;
    int rc;
    char buf[TCPMW_BUFLEN];
    zlog_info(zc_tcp, "New sock thread started, waiting for requests");
    while ((rc=read(args->fd, buf, sizeof(buf))) > 0) {
        /* zlog_info(zc_tcp, "read %u bytes from %d: %.*s", rc, args->fd, rc, buf); */
        if (rc < CMD_SIZE){
            zlog_error(zc_tcp, "tcpmw_sock_thread: command too short");
            continue;
        }
        if (!strncmp(buf, CMD_SEND, CMD_SIZE))
            tcpmw_send(args, buf, rc);
        else if (!strncmp(buf, CMD_RECV, CMD_SIZE))
            tcpmw_recv(args);
        else if (!strncmp(buf, CMD_BIND, CMD_SIZE))
            tcpmw_bind(args, buf, rc);
        else if (!strncmp(buf, CMD_CONNECT, CMD_SIZE))
            tcpmw_connect(args, buf, rc);
        else if (!strncmp(buf, CMD_LISTEN, CMD_SIZE))
            tcpmw_listen(args);
        else if (!strncmp(buf, CMD_ACCEPT, CMD_SIZE))
            tcpmw_accept(args, buf, rc);
        else if (!strncmp(buf, CMD_SET_RECV_TOUT, CMD_SIZE))
            tcpmw_set_recv_tout(args, buf, rc);
        else if (!strncmp(buf, CMD_GET_RECV_TOUT, CMD_SIZE))
            tcpmw_get_recv_tout(args);
        else if (!strncmp(buf, CMD_CLOSE, CMD_SIZE)){
            tcpmw_close(args);
            break;
        }
    }
    if (rc == -1) {
        zlog_error(zc_tcp, "tcpmw_sock_thread: read() failed");
        tcpmw_close(args);
    }
    else if (rc == 0) {
        zlog_info(zc_tcp, "tcpmw_sock_thread: EOF");
        tcpmw_close(args);
    }
    zlog_info(zc_tcp, "tcpmw_sock_thread: leaving");
    return 0;
}

void tcpmw_bind(struct conn_args *args, char *buf, int len){
    ip_addr_t addr;
    u16_t port, svc;
    char *p = buf;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "BIND received");
    if ((len < CMD_SIZE + 5 + ADDR_NONE_LEN) || (len > CMD_SIZE + 5 + ADDR_IPV6_LEN)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong command");
        goto reply;
    }

    p += CMD_SIZE;  /* skip CMD_BIND */
    port = *((u16_t *)p);
    p += 2;  /* skip port */
    svc = *((u16_t *)p);
    p += 2;  /* skip SVC */
    args->conn->pcb.ip->svc = svc;  /* set svc for TCP/IP context */
    scion_addr_from_raw(&addr, p[0], p + 1);
    /* TODO(PSz): test bind with addr = NULL */
    if ((lwip_err = netconn_bind(args->conn, &addr, port)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_bind() failed");
        goto reply;
    }
    zlog_info(zc_tcp, "tcpmw_bind(): bound port %d, svc: %d", port, svc);

reply:
    tcpmw_reply(args->fd, CMD_BIND);
}

void tcpmw_connect(struct conn_args *args, char *buf, int len){
    ip_addr_t addr;
    u16_t port, path_len;
    char *p = buf;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "CONN received");
    p += CMD_SIZE;  /* skip CMD_CONNECT */
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
    if (p[0] == ADDR_SVC_TYPE)  /* set svc for TCP/IP context */
        args->conn->pcb.ip->svc = ntohs(*(u16_t*)(p + ISD_AS_LEN + 1));
    /* Set first hop. */
    p += 1 + ISD_AS_LEN + get_addr_len(p[0]);  /* TODO(PSz): don't assume IPv4 */
    path->first_hop.sin_family = AF_INET;
    memcpy(&(path->first_hop.sin_addr), p, 4);
    path->first_hop.sin_port = htons(*(uint16_t *)(p + 4));

    if ((lwip_err = netconn_connect(args->conn, &addr, port)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_connect(): netconn_connect() failed");

    tcpmw_reply(args->fd, CMD_CONNECT);
}

void tcpmw_listen(struct conn_args *args){
    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "LIST received");
    if ((lwip_err = netconn_listen(args->conn)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_listen() failed");

    tcpmw_reply(args->fd, CMD_LISTEN);
}

void tcpmw_accept(struct conn_args *args, char *buf, int len){
    int new_fd;
    char accept_path[strlen(LWIP_SOCK_DIR) + SOCK_PATH_LEN];
    struct sockaddr_un addr;
    struct netconn *newconn;

    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "ACCE received");
    if (len != CMD_SIZE + SOCK_PATH_LEN){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_accept(): incorrect ACCE length");
        goto fail;
    }

    if ((lwip_err = netconn_accept(args->conn, &newconn)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_accept(): netconn_accept() failed");
        goto fail;
    }
    zlog_info(zc_tcp, "tcpmw_accept(): waiting...");

    sprintf(accept_path, "%s%.*s", LWIP_SOCK_DIR, SOCK_PATH_LEN, buf + CMD_SIZE);
    zlog_info(zc_tcp, "connecting to %s", accept_path);
    if ((new_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): socket() failed");
        goto fail;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, accept_path, sizeof(addr.sun_path)-1);
    if (connect(new_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): connect() to %s failed", accept_path);
        goto fail;
    }

    /* Create a detached thread. */
    pthread_attr_t attr;
    pthread_t tid;
    if (pthread_attr_init(&attr)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): attribute init failed");
        goto fail;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): setting detached state failed");
        goto fail;
    }
    struct conn_args *new_args = malloc(sizeof *new_args);
    new_args->fd = new_fd;
    new_args->conn = newconn;
    if (pthread_create(&tid, &attr, &tcpmw_sock_thread, new_args)){
        sys_err = errno;
        zlog_error(zc_tcp, "tcpmw_accept(): pthread_create() failed");
        free(new_args);
        goto fail;
    }

    /* Letting know that new thread is ready. */
    u8_t *tmp, *p, haddr_len;
    u16_t tot_len, path_len = newconn->pcb.ip->path->len;
    haddr_len = get_addr_len(newconn->pcb.ip->remote_ip.type);
    tot_len = RESP_SIZE + 2 + path_len + 1 + 4 + haddr_len;

    tmp = malloc(tot_len);
    p = tmp;
    memcpy(p, CMD_ACCEPT, RESP_SIZE - 1);
    p[RESP_SIZE - 1] = ERR_OK;
    p += RESP_SIZE;
    *((u16_t *)(p)) = path_len;
    p += 2;
    memcpy(p, newconn->pcb.ip->path->raw_path, path_len);
    p += path_len;
    p[0] = newconn->pcb.ip->remote_ip.type;
    p++;
    memcpy(p, newconn->pcb.ip->remote_ip.addr, 4 + haddr_len);
    write(args->fd, tmp, tot_len);
    /* Confirm it is ok, by sending CMD_ACCEPT+ERR_OK only */
    write(new_fd, tmp, RESP_SIZE);
    free(tmp);
    return;

fail:
    tcpmw_reply(args->fd, CMD_ACCEPT);
}

void tcpmw_send(struct conn_args *args, char *buf, int len){
    char *p = buf;
    u32_t size;
    size_t written;

    lwip_err = 0;
    sys_err = 0;
    p += CMD_SIZE;  /* skip CMD_SEND */
    len -= CMD_SIZE;
    size = *((u32_t *)p);
    p += 4;  /* skip total size */
    len -= 4;  /* how many bytes local read() has read. */
    zlog_info(zc_tcp, "SEND received (%dB to send, locally received: %dB)", size, len);

    /* This is implemented more like send_all(). If this is not desired, we */
    /* could allocate temporary buf or sync buf size with python's send(). */
    while (1){
        if (len > size){
            lwip_err = ERR_MW;
            zlog_error(zc_tcp, "tcpmw_send(): received more than to send");
            goto reply;
        }
        if ((lwip_err = netconn_write_partly(args->conn, p, len, NETCONN_COPY, &written)) != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send(): netconn_write() failed");
            zlog_debug(zc_tcp, "netconn_write(): len/written/size: %d/%lu/%d", len, written, size);
            goto reply;
        }
        zlog_debug(zc_tcp, "netconn_write(): len/written/size: %d/%lu/%d", len, written, size);
        size -= written;
        len -= written;
        if (!size)  /* done */
            break;
        if (len > 0){  /* write again from current buf */
            p += written;
            continue;
        }
        /* read new part from app */
        len = read(args->fd, buf, TCPMW_BUFLEN);
        if (len < 1){
            sys_err = errno;
            zlog_error(zc_tcp, "tcpmw_send(): local sock read() error");
            goto reply;
        }
        p = buf;
    }

reply:
    tcpmw_reply(args->fd, CMD_SEND);
}

void tcpmw_recv(struct conn_args *args){
    char *msg;
    struct netbuf *buf;
    void *data;
    u16_t len;

    lwip_err = 0;
    sys_err = 0;
    if ((lwip_err = netconn_recv(args->conn, &buf)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_recv(): netconn_recv() failed");
        goto fail;
    }

    if ((lwip_err = netbuf_data(buf, &data, &len)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_recv(): netbuf_data() failed");
        goto fail;
    }

    msg = malloc(len + RESP_SIZE + 2);
    memcpy(msg, CMD_RECV, RESP_SIZE - 1);
    msg[RESP_SIZE - 1] = ERR_OK;
    *((u16_t *)(msg + RESP_SIZE)) = len;
    memcpy(msg + RESP_SIZE + 2, data, len);
    write(args->fd, msg, len + RESP_SIZE + 2);
    netbuf_delete(buf);
    free(msg);
    return;

fail:
    tcpmw_reply(args->fd, CMD_RECV);
}

void tcpmw_set_recv_tout(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "SRTO received");
    if (len != CMD_SIZE + 4){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_recv_tout(): incorrect SRTO length");
        goto reply;
    }

    int timeout = (int)*(u32_t *)(buf + CMD_SIZE);
    fprintf(stderr, "TOUT: %d\n", timeout);
    netconn_set_recvtimeout(args->conn, timeout);

reply:
    tcpmw_reply(args->fd, CMD_SET_RECV_TOUT);
}

void tcpmw_get_recv_tout(struct conn_args *args){
    zlog_info(zc_tcp, "GRTO received");
    int timeout = netconn_get_recvtimeout(args->conn);
    char *msg = malloc(RESP_SIZE + 4);
    memcpy(msg, CMD_GET_RECV_TOUT, RESP_SIZE - 1);
    msg[RESP_SIZE - 1] = ERR_OK;
    *(u32_t *)(msg + RESP_SIZE) = (u32_t)timeout;
    write(args->fd, msg, RESP_SIZE + 4);
    free(msg);
}

void tcpmw_close(struct conn_args *args){
    close(args->fd);
    netconn_close(args->conn);
    netconn_delete(args->conn);
    args->conn = NULL;
    free(args);
}
