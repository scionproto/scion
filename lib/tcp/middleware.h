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
#ifndef _MIDDLEWARE_H_
#define _MIDDLEWARE_H_

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "lwip/api.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "libscion/scion.h"
#include "zlog.h"

#define LWIP_SOCK_DIR (DISPATCHER_DIR "/lwip")
#define SOCK_PATH_LEN 36  /* of "accept" socket */
#define CMD_SIZE 4
#define RESP_SIZE (CMD_SIZE + 1)
#define TCPMW_BUFLEN 8192
#define PLD_SIZE 2  /* Each command/reply is prepended with 2B payload len field. */
#define ERR_NEW -126  /* netconn_new() error. */
#define ERR_MW -127  /* API/TCP middleware error. */
#define ERR_SYS -128  /* All system errors are mapped to this LWIP's code. */
#define TCP_POLLING_TOUT 2  /* Polling timeout (in ms) used within tcpmw_pipe_loop */
#define MAX_CONNECTIONS 8192  /* Max number of active TCP connections */

/* Middleware API commands */
#define CMD_ACCEPT "ACCE"
#define CMD_BIND "BIND"
#define CMD_CLOSE "CLOS"
#define CMD_CONNECT "CONN"
#define CMD_GET_RECV_TOUT "GRTO"
#define CMD_LISTEN "LIST"
#define CMD_NEW_SOCK "NEWS"
#define CMD_SET_RECV_TOUT "SRTO"
#define CMD_SET_OPT "SOPT"
#define CMD_RESET_OPT "ROPT"
#define CMD_GET_OPT "GOPT"

#define CMD_CMP(buf, cmd) (!strncmp(buf, cmd, CMD_SIZE))

zlog_category_t *zc_tcp;

/* TODO(PSz): replace by struct conn_state at some point */
struct conn_args{
    int fd;
    struct netconn *conn;
};

struct conn_state{
	int fd;  /* Socket: App <-> MW */
    struct netconn *conn;  /* Socket: MW <-> TCP stack */
    char *app_buf;  /* Data from app -> TCP stack */
    int app_buf_len;  /* Its len */
    int app_buf_written;  /* Bytes sent already to TCP */
    struct netbuf *_netbuf;  /* Raw netconn buffer */
    char *tcp_buf;  /* Data from TCP -> app */
    int tcp_buf_len;  /* Its len */
    int tcp_buf_written;  /* Bytes sent already to app */
    int active;  /* Whether the structure is used */
};

static struct conn_state connections[MAX_CONNECTIONS];
static struct pollfd pollfds[MAX_CONNECTIONS];
struct conn_state* tcpmw_conn2state(struct netconn *);
struct conn_state* tcpmw_fd2state(int fd);

void *tcpmw_main_thread(void *);
void tcpmw_init();
void *tcpmw_sock_thread(void *);
void tcpmw_socket(int);
int tcpmw_add_connection(struct conn_args *);
void tcpmw_clear_state(struct conn_state *, int);
void tcpmw_clear_fd_state(struct conn_state *, int);
void tcpmw_clear_conn_state(struct conn_state *, int);
void tcpmw_bind(struct conn_args *, char *, int);
s8_t tcpmw_connect(struct conn_args *, char *, int);
void tcpmw_listen(struct conn_args *, int);
void tcpmw_accept(struct conn_args *, char *, int);
void tcpmw_set_recv_tout(struct conn_args *, char *, int);
void tcpmw_get_recv_tout(struct conn_args *, int);
void tcpmw_set_sock_opt(struct conn_args *, char *, int);
void tcpmw_reset_sock_opt(struct conn_args *, char *, int);
void tcpmw_get_sock_opt(struct conn_args *, char *, int);
void tcpmw_close(struct conn_args *);
void tcpmw_reply(struct conn_args *, const char *, s8_t);
void tcpmw_terminate(struct conn_args *);
int tcpmw_read_cmd(int, char *);
void tcpmw_unlink_sock(void);
void *tcpmw_pipe_loop(void *);
void *tcpmw_poll_loop(void *);
int tcpmw_from_app_sock(struct conn_args *);
int tcpmw_from_tcp_sock(struct conn_args *);
void tcpmw_send_to_tcp(struct conn_state *);
void tcpmw_send_to_app(struct conn_state *);

#endif
