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

#include <memory>
#include <unistd.h>
#include <iostream>
#include <cstring>

#include "scion.h"
#include "SspSocket.h"

//
// Utility functions
//

// Deep copies the SCION address src into dest.
void copy_scion_addr(SCIONAddr* dest, const SCIONAddr* src)
{
  dest->isd_as = src->isd_as;
  dest->host.addr_type = src->host.addr_type;
  dest->host.port = src->host.port;
  memcpy(static_cast<uint8_t*>(dest->host.addr),
         static_cast<const uint8_t*>(src->host.addr),
         get_addr_len(src->host.addr_type));
}


//
// Src
//

// TODO(jsmith): Check address validity
int SspSocket::bind(const SCIONAddr& sockaddr)
{
  // Check if the socket is already bound
  if (m_local_addr.host.addr_type != ADDR_NONE_TYPE) {
    std::cerr << "Socket already bound.\n";
    return -EINVAL;
  }
  // Deep copy the address
  copy_scion_addr(&m_local_addr, &sockaddr);
  return 0;
}

int SspSocket::connect(const SCIONAddr& sockaddr)
{
  // Check for a closed connection and non-blocking repeated connects
  switch (m_state) {
    case SspSocket::State::CLOSED:
      if (!m_is_blocking) {
        // TODO(jsmith): Timed out/refused connection errors need to be
        // returned if the socket is non-blocking.
      }
      return active_open(sockaddr);
    case SspSocket::State::SYN_SENT:
    case SspSocket::State::SYN_RECEIVED:
      if (m_is_blocking) {
        // TODO(jsmith): Wait for state established
      } else {
        return -EINPROGRESS;
      }
    case SspSocket::State::LISTEN:
      // TODO(jsmith): Handle passive->active transition.
      throw "Not yet implemented: Transition to an active socket";
    default:  // The socket is in a connected state
      return -EISCONN;
  }
}

int SspSocket::active_open(const SCIONAddr& sockaddr)
{
  // Connect to the daemon
  // Connect to the dispatcher
  // Register our flow
  // Start the threads for sending and receiving
  // Construct and schedule the packet to be sent
  // Before sending we need to get an IP address
  // Update the internal state
  // If any of these fail, reset everything
}


SspSocket::~SspSocket()
{
}
