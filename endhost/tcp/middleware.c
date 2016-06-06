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
void tcpmw_socket(int fd){
    char buf[8];
    struct conn_args *args;
    struct netconn *conn;
    pthread_t tid;

    printf("NEWS received\n");
    if (read(fd, buf, sizeof(buf)) != CMD_SIZE){
        perror("tcpmw_socket() error on read");
        goto fail;
    }
    if (strncmp(buf, "NEWS", CMD_SIZE)){
        perror("tcpmw_socket() wrong command");
        goto fail;
    }
    conn = netconn_new(NETCONN_TCP);
    if (conn == NULL){
        perror("tcpmw_socket() failed at netconn_new()");
        goto fail;
    }

    // Create a detached thread.
    pthread_attr_t attr;
    if (pthread_attr_init(&attr)){
        perror("Attribute init failed");
        goto fail;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)){
        perror("Setting detached state failed");
        goto fail;
    }
    args = malloc(sizeof *args);
    args->fd = fd;
    args->conn = conn;
    if (pthread_create(&tid, &attr, &tcpmw_sock_thread, args)){
        perror("tcpmw_accept() error at pthread_create()");
        free(args);
        goto fail;
    }
    write(fd, "NEWSOK", RESP_SIZE);
    return;

fail:
    write(fd, "NEWSER", RESP_SIZE);
    close(fd);
    return;
}

void tcpmw_bind(struct conn_args *args, char *buf, int len){
    ip_addr_t addr;
    u16_t port, svc;
    char *p = buf;
    printf("BIND received\n");
    if ((len < CMD_SIZE + 5 + ADDR_NONE_LEN) || (len > CMD_SIZE + 5 + ADDR_IPV6_LEN)){
        write(args->fd, "BINDER", RESP_SIZE);
        goto fail;
    }

    p += CMD_SIZE; // skip "BIND"
    port = *((u16_t *)p);
    p += 2; // skip port
    svc = *((u16_t *)p); // SVC Address
    p += 2; // skip svc
    args->conn->pcb.ip->svc = svc; // set svc for TCP/IP context
    scion_addr_raw(&addr, p[0], p + 1);
    // TODO(PSz): test bind with addr = NULL
    if (netconn_bind(args->conn, &addr, port) != ERR_OK){
        perror("tcpmw_bind() error at netconn_bind()\n");
        goto fail;
    }
    fprintf(stderr, "Bound port %d, svc: %d, and addr:", port, svc);
    print_scion_addr(&addr);
    write(args->fd, "BINDOK", RESP_SIZE);
    return;

fail:
    write(args->fd, "BINDER", RESP_SIZE);
    return;
}

void tcpmw_connect(struct conn_args *args, char *buf, int len){
    // Some sanity checks with len etc...
    ip_addr_t addr;
    u16_t port, path_len;
    char *p = buf;

    printf("CONN received\n");
    p += CMD_SIZE; // skip "CONN"
    port = *((u16_t *)p);
    p += 2; // skip port
    path_len = *((u16_t *)p);
    p += 2; // skip path_len

    // add path to TCP/IP state
    spath_t *path = malloc(sizeof *path);
    path->raw_path = malloc(path_len);
    memcpy(path->raw_path, p, path_len);
    path->len = path_len;
    args->conn->pcb.ip->path = path;
    fprintf(stderr, "Path added, len %d\n", path_len);

    p += path_len; // skip path
    scion_addr_raw(&addr, p[0], p + 1);
    print_scion_addr(&addr);
    if (p[0] == ADDR_SVC_TYPE)  // set svc for TCP/IP context
        args->conn->pcb.ip->svc = ntohs(*(u16_t*)(p + ISD_AS_LEN + 1));
    // Set first hop.
    p += 1 + ISD_AS_LEN + get_addr_len(p[0]);
    path->first_hop.sin_family = AF_INET;
    memcpy(&(path->first_hop.sin_addr), p, 4); // TODO(PSz): don't assume IPv4
    path->first_hop.sin_port = htons(*(uint16_t *)(p + 4));

    if (netconn_connect(args->conn, &addr, port) != ERR_OK){
        perror("tcpmw_connect() error at netconn_connect()\n");
        // Path is freed in tcpmw_pcb_remove()
        goto fail;
    }
    write(args->fd, "CONNOK", RESP_SIZE);
    return;

fail:
    write(args->fd, "CONNER", RESP_SIZE);
    return;
}

void tcpmw_listen(struct conn_args *args){
    printf("LIST received\n");
    if (netconn_listen(args->conn) != ERR_OK){
        perror("tcpmw_bind() error at netconn_listen()\n");
        goto fail;
    }
    write(args->fd, "LISTOK", RESP_SIZE);
    return;

fail:
    write(args->fd, "LISTER", RESP_SIZE);
    return;
}

void tcpmw_accept(struct conn_args *args, char *buf, int len){
    int new_fd;
    char accept_path[strlen(LWIP_SOCK_DIR) + SOCK_PATH_LEN];
    struct sockaddr_un addr;
    struct netconn *newconn;

    printf("ACCE received\n");
    if (len != CMD_SIZE + SOCK_PATH_LEN){
        perror("tcpmw_accept(): incorrect ACCE length\n");
        goto fail;
    }

    if (netconn_accept(args->conn, &newconn) != ERR_OK){
        perror("tcpmw_accept() error at netconn_accept()\n");
        goto fail;
    }
    fprintf(stderr, "tcpmw_accept(): waiting...\n");

    sprintf(accept_path, "%s%.*s", LWIP_SOCK_DIR, SOCK_PATH_LEN, buf + CMD_SIZE);
    fprintf(stderr, "Will connect to %s\n", accept_path);
    if ((new_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("tcpmw_accept() error at socket()\n");
        goto fail;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, accept_path, sizeof(addr.sun_path)-1);
    if (connect(new_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("tcpmw_accept() error at connect()\n");
        fprintf(stderr, "failed connection to %s\n", accept_path);
        goto fail;
    }

    // Create a detached thread.
    pthread_attr_t attr;
    pthread_t tid;
    if (pthread_attr_init(&attr)){
        perror("Attribute init failed");
        goto fail;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)){
        perror("Setting detached state failed");
        goto fail;
    }
    struct conn_args *new_args = malloc(sizeof *new_args);
    new_args->fd = new_fd;
    new_args->conn = newconn;
    if (pthread_create(&tid, &attr, &tcpmw_sock_thread, new_args)){
        perror("tcpmw_accept() error at pthread_create()\n");
        free(new_args);
        goto fail;
    }

    // Letting know that new thread is ready.
    u8_t *tmp, *p, haddr_len;
    u16_t tot_len, path_len = newconn->pcb.ip->path->len;
    haddr_len = get_addr_len(newconn->pcb.ip->remote_ip.type);
    tot_len = RESP_SIZE + 2 + path_len + 1 + 4 + haddr_len;

    tmp = malloc(tot_len);
    p = tmp;
    memcpy(p, "ACCEOK", RESP_SIZE);
    p += RESP_SIZE;
    *((u16_t *)(p)) = path_len;
    p += 2;
    memcpy(p, newconn->pcb.ip->path->raw_path, path_len);
    p += path_len;
    p[0] = newconn->pcb.ip->remote_ip.type;
    p++;
    memcpy(p, newconn->pcb.ip->remote_ip.addr, 4 + haddr_len);
    write(args->fd, tmp, tot_len);
    write(new_fd, "ACCEOK", RESP_SIZE); // confirm it is ok.
    free(tmp);
    return;

fail:
    write(args->fd, "ACCEER", RESP_SIZE);
    return;
}

void tcpmw_send(struct conn_args *args, char *buf, int len){
    char *p = buf;
    u32_t size;
    size_t written;

    p += CMD_SIZE; // skip "SEND"
    len -= CMD_SIZE;
    size = *((u32_t *)p);
    p += 4; // skip total size
    len -= 4; // how many bytes local read() has read.
    printf("SEND received (%d bytes to send, locally received: %d)\n", size, len);

    // This is implemented more like send_all(). If this is not desired, we
    // could allocate temporary buf or sync buf size with python's send().
    while (1){
        if (len > size){
            perror("tcpmw_send() error: received more than to send\n");
            goto fail;
        }
        if (netconn_write_partly(args->conn, p, len, NETCONN_COPY, &written) != ERR_OK){
            perror("tcpmw_send() error at netconn_write()\n");
            printf("NETCONN PARTLY BROKEN: %d, %lu, %d\n", len, written, size);
            goto fail;
        }
        printf("NETCONN PARTLY OK: %d, %lu, %d\n", len, written, size);
        size -= written;
        len -= written;
        if (!size) // done
            break;
        if (len > 0){ // write again from current buf
            p += written;
            continue;
        }
        // read new part from app
        len=read(args->fd, buf, TCPMW_BUFLEN);
        if (len < 1){
            perror("tcpmw_send() error at local sock read()\n");
            goto fail;
        }
        p = buf;
    }
    write(args->fd, "SENDOK", RESP_SIZE);
    return;

fail:
    write(args->fd, "SENDER", RESP_SIZE);
    return;
}

void tcpmw_recv(struct conn_args *args){
    char *msg;
    struct netbuf *buf;
    void *data;
    u16_t len;

    if (netconn_recv(args->conn, &buf) != ERR_OK){
        perror("tcpmw_recv() error at netconn_recv()\n");
        // TODO(PSz): other errors (especially check if buf has to be freed).
        goto fail;
    }

    if (netbuf_data(buf, &data, &len) != ERR_OK){
        perror("tcpmw_recv() error at netbuf_data()\n");
        goto fail;
    }

    msg = malloc(len + RESP_SIZE + 2);
    memcpy(msg, "RECVOK", RESP_SIZE);
    *((u16_t *)(msg + RESP_SIZE)) = len;
    memcpy(msg + RESP_SIZE + 2, data, len);
    write(args->fd, msg, len + RESP_SIZE + 2);
    netbuf_delete(buf);
    free(msg);
    return;

fail:
    write(args->fd, "RECVER", RESP_SIZE);
    return;
}

void tcpmw_close(struct conn_args *args){
    close(args->fd);
    netconn_close(args->conn);
    netconn_delete(args->conn);
    args->conn = NULL;
    free(args);
}

void *tcpmw_sock_thread(void *data){
    struct conn_args *args = data;
    int rc;
    char buf[TCPMW_BUFLEN];
    fprintf(stderr, "started, waiting for requests\n");
    while ((rc=read(args->fd, buf, sizeof(buf))) > 0) {
        printf("read %u bytes from %d: %.*s\n", rc, args->fd, rc, buf);
        if (rc < CMD_SIZE){
            perror("command too short\n");
            continue;
        }
        if (!strncmp(buf, "SEND", CMD_SIZE))
            tcpmw_send(args, buf, rc);
        else if (!strncmp(buf, "RECV", CMD_SIZE))
            tcpmw_recv(args);
        else if (!strncmp(buf, "BIND", CMD_SIZE))
            tcpmw_bind(args, buf, rc);
        else if (!strncmp(buf, "CONN", CMD_SIZE))
            tcpmw_connect(args, buf, rc);
        else if (!strncmp(buf, "LIST", CMD_SIZE))
            tcpmw_listen(args);
        else if (!strncmp(buf, "ACCE", CMD_SIZE))
            tcpmw_accept(args, buf, rc);
        else if (!strncmp(buf, "CLOS", CMD_SIZE)){
            tcpmw_close(args);
            break;
        }
    }
    if (rc == -1) {
        perror("read");
        tcpmw_close(args);
    }
    else if (rc == 0) {
        printf("EOF\n");
        tcpmw_close(args);
    }
    printf("Leaving tcpmw_sock_thread\n");
    return 0;
}

void *tcpmw_main_thread(void) {
    struct sockaddr_un addr;
    int fd, cl;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    mkdir(LWIP_SOCK_DIR, 0755);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, RPCD_SOCKET, sizeof(addr.sun_path)-1);
    unlink(RPCD_SOCKET);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (listen(fd, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    while (1) {
        if ((cl = accept(fd, NULL, NULL)) == -1) {
            perror("accept error");
            continue;
        }
        // socket() called by app. Create a netconn and a coresponding thread.
        tcpmw_socket(cl);
    }
    return 0;
}

