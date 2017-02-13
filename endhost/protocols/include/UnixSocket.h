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
#ifndef UNIX_SOCKET_H_
#define UNIX_SOCKET_H_

#include <cstdint>
#include <sys/socket.h>


/* Thin wrapper around Unix sockets to enable decoupling the tests from the
 * Linux system calls.
 */
class UnixSocket {
public:
  UnixSocket() = default;
  virtual ~UnixSocket();

  /* Returns zero on sucess or -1 on failure, and sets errno appropriately. */
  virtual int connect(const char* addr);
  virtual int recv_all(uint8_t *buf, int len);
  virtual int send_all(uint8_t *buf, int len);
	virtual int setsockopt(int level, int optname, const void *optval,
												 socklen_t optlen);

  virtual int close();

private:
  int m_sock_fd{0};

  // Unsuported default operations
  UnixSocket(const UnixSocket&) = delete;
  UnixSocket& operator=(const UnixSocket&) = delete;
  UnixSocket(UnixSocket&&) = delete;
  UnixSocket& operator=(UnixSocket&&) = delete;
};

#endif /* ifndef UNIX_SOCKET_H_ */
