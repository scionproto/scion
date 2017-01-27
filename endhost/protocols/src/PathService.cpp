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

#include <string.h>
#include <unistd.h>
#include <cstring>

#include <memory>
#include <iostream>

#include "util.h"
#include "PathService.h"

PathService::~PathService()
{
  // Close the socket
  if (close(m_daemon_sockfd) != 0) {
    std::cerr << "Error sciond socket close: " << std::strerror(errno) << "\n";
  }
}

std::unique_ptr<PathService> PathService::create(const char* daemon_addr,
                                                 int* error)
{
  // Create a new service instance
  std::unique_ptr<PathService> service{new PathService()};

  // Connect to daemon and hanlde any errors
  int result = daemon_connect(daemon_addr);
  if (result >= 0) {
    service->m_daemon_sockfd = result;
  } else {
    *error = result;
    service = nullptr;  // Free the memory
  }
  return service;
}
