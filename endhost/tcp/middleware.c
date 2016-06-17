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

/* FIXME(PSz): due to specifics of this middleware (UNIX sockets and sequential
 * blocking API), single recv() and send() are used. In general it is safer to
 * use send_all()/recv_all() (to send/receive exactly how much is needed). */

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
    char buf[8];
    int count;
    struct conn_args *args;
    struct netconn *conn;
    pthread_t tid;

    lwip_err = 0;
    sys_err = 0;
    if ((count = read(fd, buf, sizeof(buf))) != CMD_SIZE){
        if (count < 0){
            sys_err = errno;
            zlog_error(zc_tcp, "tcpmw_socket(): read(): %s", strerror(errno));
        }
        else{
            lwip_err = ERR_MW;
            zlog_error(zc_tcp, "tcpmw_socket(): wrong command: %.*s", count, buf);
        }
        goto close;
    }
    if (strncmp(buf, CMD_NEW_SOCK, CMD_SIZE)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_socket(): wrong command: %.*s", count, buf);
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
close:
    close(fd);
exit:
    tcpmw_reply(fd, CMD_NEW_SOCK);
}

void tcpmw_reply(int fd, const char *cmd){
    char buf[RESP_SIZE];
    if (sys_err)
        lwip_err = ERR_SYS;
    memcpy(buf, cmd, CMD_SIZE);
    buf[RESP_SIZE - 1] = lwip_err;  /* Set error code. */
    write(fd, buf, RESP_SIZE);
}

void *tcpmw_sock_thread(void *data){
    struct conn_args *args = data;
    int rc;
    char buf[TCPMW_BUFLEN];
    zlog_info(zc_tcp, "New sock thread started, waiting for requests");
    while ((rc=read(args->fd, buf, sizeof(buf))) > 0) {
        if (rc < CMD_SIZE){
            zlog_error(zc_tcp, "tcpmw_sock_thread: command too short: %.*s", rc, buf);
            break;
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
        else if (!strncmp(buf, CMD_CLOSE, CMD_SIZE))
            break;
        else{
            zlog_error(zc_tcp, "tcpmw_sock_thread: command not found: %.*s", CMD_SIZE, buf);
            break;
        }
    }
    if (rc == -1)
        zlog_error(zc_tcp, "tcpmw_sock_thread: read(): %s", strerror(errno));
    else if (rc == 0)
        zlog_info(zc_tcp, "tcpmw_sock_thread: EOF");
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
    if ((len < CMD_SIZE + 5 + ADDR_NONE_LEN) || (len > CMD_SIZE + 5 + ADDR_IPV6_LEN)){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_bind(): wrong command");
        goto exit;
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
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_bind(): %s", lwip_strerr(lwip_err));
        goto exit;
    }
    char host_str[MAX_HOST_ADDR_STR];
    uint32_t isd_as = *(uint32_t*)addr.addr;
    format_host(addr.type, addr.addr, host_str, sizeof(host_str));
    zlog_info(zc_tcp, "tcpmw_bind(): bound:%d-%d ,%s port %d, svc: %d",
              ISD(isd_as), AS(isd_as), host_str, port, svc);

exit:
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

    tcpmw_reply(args->fd, CMD_CONNECT);
}

void tcpmw_listen(struct conn_args *args){
    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "LIST received");
    if ((lwip_err = netconn_listen(args->conn)) != ERR_OK)
        zlog_error(zc_tcp, "tcpmw_bind(): netconn_listen(): %s", lwip_strerr(lwip_err));

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
        zlog_error(zc_tcp, "tcpmw_accept(): incorrect ACCE length %.*s", len, buf);
        goto exit;
    }

    if ((lwip_err = netconn_accept(args->conn, &newconn)) != ERR_OK){
        zlog_error(zc_tcp, "tcpmw_accept(): netconn_accept(): %s", lwip_strerr(lwip_err));
        goto exit;
    }
    zlog_info(zc_tcp, "tcpmw_accept(): waiting...");

    sprintf(accept_path, "%s%.*s", LWIP_SOCK_DIR, SOCK_PATH_LEN, buf + CMD_SIZE);
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
    u16_t tot_len = RESP_SIZE + 2 + path_len + 1 + 4 + haddr_len;

    u8_t *tmp = malloc(tot_len);
    u8_t *p = tmp;
    /* First CMD_ACCEPT+ERR_OK */
    memcpy(p, CMD_ACCEPT, RESP_SIZE - 1);
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
    write(new_fd, tmp, tot_len);
    free(tmp);
    /* Confirm, by sending CMD_ACCEPT+ERR_OK to the "old" socket. */

exit:
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
    /* could allocate temporary buf. */
    while (1){
        if (len > size){
            lwip_err = ERR_MW;
            zlog_error(zc_tcp, "tcpmw_send(): received more than to send");
            goto exit;
        }
        if ((lwip_err = netconn_write_partly(args->conn, p, len, NETCONN_COPY, &written)) != ERR_OK){
            zlog_error(zc_tcp, "tcpmw_send(): netconn_write(): %s", lwip_strerr(lwip_err));
            zlog_debug(zc_tcp, "netconn_write(): buffered/total_written/total_size: %d/%lu/%d",
                       len, written, size);
            goto exit;
        }
        zlog_debug(zc_tcp, "netconn_write(): buffered/total_written/total_size: %d/%lu/%d",
                   len, written, size);
        size -= written;
        len -= written;
        if (!size)  /* done */
            break;
        if (len > 0){  /* write again from current buf */
            p += written;
            continue;
        }
        /* read new part from app */
        if ((len = read(args->fd, buf, TCPMW_BUFLEN)) < 1){
            if (len < 0){
                sys_err = errno;
                zlog_error(zc_tcp, "tcpmw_send(): read(): %s", strerror(errno));
            }
            else{
                lwip_err = ERR_MW;
                zlog_error(zc_tcp, "tcpmw_send(): read() unexpected EOF");
            }
            goto exit;
        }
        p = buf;
    }

exit:
    tcpmw_reply(args->fd, CMD_SEND);
}

void tcpmw_recv(struct conn_args *args){
    char *msg;
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

    msg = malloc(len + RESP_SIZE + 2);
    memcpy(msg, CMD_RECV, CMD_SIZE);
    msg[RESP_SIZE - 1] = ERR_OK;
    *((u16_t *)(msg + RESP_SIZE)) = len;
    memcpy(msg + RESP_SIZE + 2, data, len);
    write(args->fd, msg, len + RESP_SIZE + 2);
    netbuf_delete(buf);
    free(msg);
    return;

exit:
    tcpmw_reply(args->fd, CMD_RECV);
}

void tcpmw_set_recv_tout(struct conn_args *args, char *buf, int len){
    lwip_err = 0;
    sys_err = 0;
    zlog_info(zc_tcp, "SRTO received");
    if (len != CMD_SIZE + 4){
        lwip_err = ERR_MW;
        zlog_error(zc_tcp, "tcpmw_set_recv_tout(): incorrect SRTO length");
        goto exit;
    }

    int timeout = (int)*(u32_t *)(buf + CMD_SIZE);
    netconn_set_recvtimeout(args->conn, timeout);

exit:
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
