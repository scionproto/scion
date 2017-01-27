// Copyright 2017 ETH Zürich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"

int daemon_connect(const char* daemon_addr)
{
  // Create a unix socket
  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd == -1) {
    return -errno;
  }

  // Define the UNIX address
  struct sockaddr_un sock_addr;
  sock_addr.sun_family = AF_UNIX;
  strncpy(sock_addr.sun_path, daemon_addr, sizeof(sock_addr.sun_path));
  // Null the final byte of the sun_path, in case the address was too long.
  sock_addr.sun_path[sizeof(sock_addr.sun_path)-1] = '\0';

  // Connect to the daemon
  if(connect(sockfd, (struct sockaddr*)(&sock_addr), sizeof(sock_addr)) == -1) {
    // Store the errno as close may overwrite it
    int connect_error = errno;
    // Cleanup the socket file descriptor
    assert(close(sockfd) == 0);
    return -connect_error;
  } else {
    return sockfd;
  }
}
