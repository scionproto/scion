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
#include <stdint.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "util.h"
#include "utils.h"
#include "defines.h"
#include "scion.h"


int clear_sock(int sockfd)
{
  const int buffer_len = 12;  // Arbitrarily chosen
  uint8_t buffer[buffer_len];
  int total_bytes = 0;
  int bytes_read = 0;

  do {  // Read data until the socket would block
    bytes_read = recv(sockfd, buffer, buffer_len, MSG_DONTWAIT);

    if (bytes_read == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return total_bytes;
      } else {
        return -errno;  // Error occured while trying to clear the socket
      }
    } else {
      total_bytes += bytes_read;
    }
  } while(1);
}


int unix_connect(const char* addr)
{
  // Create a unix socket
  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd == -1) {
    return -errno;
  }

  // Define the UNIX address
  struct sockaddr_un sock_addr;
  sock_addr.sun_family = AF_UNIX;
  strncpy(sock_addr.sun_path, addr, sizeof(sock_addr.sun_path));
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


int poll_recv(int sockfd, uint8_t *buffer, size_t len, int timeout)
{
  // Define the poll struct to be notifed of data to be read
  struct pollfd poll_file;
  poll_file.fd = sockfd;
  poll_file.events = POLLIN;

  // Block until data or timeout
  int result = poll(&poll_file, /*nfds=*/1, timeout);
  if (result == -1) {
    return -errno;
  } else if (result == 0) {
    return -ETIMEDOUT;
  }

  // Read the available data
  result = recv(sockfd, buffer, len, /*flags=*/0x00);
  return (result == -1) ? -errno : result;
}
