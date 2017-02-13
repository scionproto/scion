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

#ifndef MOCK_UNIX_SOCKET_H_
#define MOCK_UNIX_SOCKET_H_

#include <cstdint>
#include <sys/socket.h>

#include "gmock/gmock.h"
#include "UnixSocket.h"

class MockUnixSocket: public UnixSocket {
public:
  MOCK_METHOD1(connect, int(const char* addr));
  MOCK_METHOD2(recv_all, int(uint8_t *buf, int len));
  MOCK_METHOD2(send_all, int(uint8_t *buf, int len));
  MOCK_METHOD4(setsockopt, int(int level, int optname, const void *optval,
                               socklen_t optlen));
  MOCK_METHOD0(close, int());
};

#endif /* ifndef MOCK_UNIX_SOCKET_H_ */
