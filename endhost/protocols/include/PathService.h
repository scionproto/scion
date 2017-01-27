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

#ifndef PATH_SERVICE_H_
#define PATH_SERVICE_H_

#include <memory>


// SCION daemon interface and path store.
//
// This service is responsible for fetching and verifying path data.
//
// TODO(jsmith): As it will be used by both the sending and receiving threads,
// we need to lock certain operations on a mutex, such as those utilizing and
// modifying the user's path preferences
class PathService {
public:
  ~PathService();

  // Create a new instance of the path service.
  //
  // @param daemon_addr The AF_UNIX address of the SCION daemon.
  // @param[out] error On success, 'error' is set to zero. Otherwise it is set
  //                   to a negative Linux system error code pertaining to the
  //                   error.
  static std::unique_ptr<PathService> create(const char* daemon_addr,
                                             int* error);

private:
  PathService() = default;

  int m_daemon_sockfd;

  // Unsuported default operations
  PathService(const PathService&) = delete;
  PathService& operator=(const PathService&) = delete;
  PathService(PathService&&) = delete;
  PathService& operator=(PathService&&) = delete;
};

#endif  // PATH_SERVICE_H_
