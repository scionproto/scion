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

#include <errno.h>
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
#include "libscion/address.h"
#include "zlog.h"

#define LWIP_SOCK_DIR "/run/shm/lwip/"
#define TCPMW_SOCKET "/run/shm/lwip/lwip"
#define SOCK_PATH_LEN 36  /* of "accept" socket */
#define CMD_SIZE 4
#define RESP_SIZE (CMD_SIZE + 1)
#define TCPMW_BUFLEN 1024
#define ERR_NEW -126  /* netconn_new() error. */
#define ERR_MW -127  /* API/TCP middleware error. */
#define ERR_SYS -128  /* All system errors are mapped to this LWIP's code. */

/* Middleware API commands */
#define CMD_ACCEPT "ACCE"
#define CMD_BIND "BIND"
#define CMD_CLOSE "CLOS"
#define CMD_CONNECT "CONN"
#define CMD_GET_RECV_TOUT "GRTO"
#define CMD_LISTEN "LIST"
#define CMD_NEW_SOCK "NEWS"
#define CMD_RECV "RECV"
#define CMD_SEND "SEND"
#define CMD_SET_RECV_TOUT "SRTO"

zlog_category_t *zc_tcp;
int sys_err;
s8_t lwip_err;

struct conn_args{
    int fd;
    struct netconn *conn;
};

void *tcpmw_main_thread(void *);
void *tcpmw_sock_thread(void *);
void tcpmw_socket(int);
void tcpmw_bind(struct conn_args *, char *, int);
void tcpmw_connect(struct conn_args *, char *, int);
void tcpmw_listen(struct conn_args *);
void tcpmw_accept(struct conn_args *, char *, int);
void tcpmw_send(struct conn_args *, char *, int);
void tcpmw_recv(struct conn_args *);
void tcpmw_set_recv_tout(struct conn_args *, char *, int);
void tcpmw_get_recv_tout(struct conn_args *);
void tcpmw_close(struct conn_args *);
void tcpmw_reply(int, const char *);

#endif
