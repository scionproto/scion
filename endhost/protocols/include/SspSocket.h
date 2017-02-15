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

#ifndef SSP_SOCKET_H_
#define SSP_SOCKET_H_

#include <memory>

#include "scion.h"
#include "ScionSocket.h"

// A socket implementing the SCION Stream Protocol for reliable multipath
// data transfer.
class SspSocket: public ScionSocket {
public:
  int bind(const SCIONAddr& sockaddr) override;
  int connect(const SCIONAddr& sockaddr) override;


private:
  // SSP protocol states analagous to TCP states.
  enum class State {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    // ESTABLISHED,
    // FIN_WAIT_1,
    // FIN_WAIT_2,
    // CLOSE_WAIT,
    // CLOSING,
    // LAST_ACK,
    // TIME_WAIT
  };


  SspSocket() = default;
  ~SspSocket() override;

  // Initiates the 3-way handshake for openning the SSP connection.
  // On success, zero is returned. On error returns a negative system error
  // code as defined for Linux connect system call.
  int active_open(const SCIONAddr& sockaddr);


  // Current SSP protocol state
  State m_state{State::CLOSED};
  // Blocking mode of the socket.
  bool m_is_blocking{true};
  // The local endpoint of the socket
  SCIONAddr m_local_addr;

  // Window and sequence number and flow state
  // See the TCP specification for a definition of the variables
  uint32_t m_send_una{0};
  uint32_t m_send_next{0};


  // Unsuported default operations
  SspSocket(const SspSocket&) = delete;
  SspSocket& operator=(const SspSocket&) = delete;
  SspSocket(SspSocket&&) = delete;
  SspSocket& operator=(SspSocket&&) = delete;
};

#endif  // SSP_SOCKET_H_
