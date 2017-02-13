/* Copyright 2017 ETH Zürich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "UnixSocket.h"

#include <cassert>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "util.h"

extern "C" {
#include "utils.h"
}

UnixSocket::~UnixSocket()
{
  int result = UnixSocket::close();
  assert(result == 0);
}


int UnixSocket::connect(const char* addr)
{
  int result = unix_connect(addr);
  if (result < 0) {
    errno = result * -1;
    return -1;
  }

  m_sock_fd = result;
  return 0;
}


int UnixSocket::recv_all(uint8_t *buf, int len)
{
  return ::recv_all(m_sock_fd, buf, len);
}


int UnixSocket::send_all(uint8_t *buf, int len)
{
  return ::send_all(m_sock_fd, buf, len);
}


int UnixSocket::setsockopt(int level, int optname, const void *optval,
                           socklen_t optlen)
{
  return ::setsockopt(m_sock_fd, level, optname, optval, optlen);
}


int UnixSocket::close()
{
  int result = ::close(m_sock_fd);
  m_sock_fd = 0;
  return result;
}
