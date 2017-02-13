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

#ifndef SCION_SOCKET_H
#define SCION_SOCKET_H

#include <sys/types.h>

#include "scion.h"

// Interface for SCION related protocol sockets.
class ScionSocket {
public:
  virtual ~ScionSocket() = default;

  // Sets the local endpoint address.
  //
  // On success, zero is returned. On error returns a negative system error
  // code as defined for Linux bind system call.
  virtual int bind(const SCIONAddr& sockaddr) = 0;

  // Connect to the specified remote socket.
  //
  // On success, zero is returned. On error returns a negative system error
  // code as defined for Linux connect system call.
  virtual int connect(const SCIONAddr& sockaddr) = 0;
};

#endif // SCION_SOCKET_H
