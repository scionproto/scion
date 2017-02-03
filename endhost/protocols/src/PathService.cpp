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
#include <poll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cstring>
#include <cmath>
#include <memory>
#include <iostream>

#include "util.h"
#include "utils.h"
#include "PathService.h"

PathService::~PathService()
{
  // Close the socket
  if (close(m_daemon_sockfd) != 0) {
    std::cerr << "Error sciond socket close: " << std::strerror(errno) << "\n";
  }
}

// std::unique_ptr<PathService> PathService::create(const char* daemon_addr,
//                                                  int* error)
// {
//   // Create a new service instance and initialize it
//   std::unique_ptr<PathService> service{new PathService()};
//
//   // Set the timeout and check the error
//   *error = service->set_timeout(0.0);
//   if (*error != 0) {
//     return nullptr;
//   }
//
//   // Connect to daemon and handle any errors
//   int result = daemon_connect(daemon_addr);
//   if (result >= 0) {
//     service->m_daemon_sockfd = result;
//   } else {
//     *error = result;
//     service = nullptr;  // Free the memory
//   }
//   return service;
// }


int PathService::set_timeout(double timeout)
{
  struct timeval timeout_val;
  // Separate the timeout into seconds and microseconds
  // FIXME(jsmith): Narrowing cast concerns here?
  timeout_val.tv_sec = time_t(std::trunc(timeout));
  timeout_val.tv_usec = suseconds_t((timeout - std::trunc(timeout)) * 1e6);

  int result = setsockopt(m_daemon_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                          &timeout_val, sizeof(timeout_val));
  return (result == -1) ? -errno : 0;
}


// TODO(jsmith): Lock
// int PathService::lookup_paths(uint32_t isd_as)
// {
//   // Clear any data pending in the socket from a previous timeout
//   int result = clear_sock(m_daemon_sockfd);
//   if (result < 0) { return result; }
//
//   // FIXME(jsmith): The upper bound is an estimation, calculate accurately.
//   const int buffer_len = 250 * m_max_paths;
//   uint8_t buffer[buffer_len];
//
//   // Send the path request
//   int data_len = write_path_request(buffer, isd_as);
//   result = send_all(m_daemon_sockfd, buffer, data_len);
//   if (result == -1) { return -errno; }
//
//   // Read  and parse the communication header
//   result = recv_all(m_daemon_sockfd, buffer, DP_HEADER_LEN);
//   if (result == -1) { return -errno; }
//
//   // Determine how much data we should expect
//   parse_dp_header(buffer, /*addr_len=*/nullptr, &data_len);
//   if (data_len == -1) {
//     return -EAGAIN;  // Possible desynchronization.
//   }
//
//   // Calculate the unwanted excess in the response
//   int excess_len = (data_len > buffer_len) ? (data_len - buffer_len) : 0;
//
//   // Read the response
//   result = recv_all(m_daemon_sockfd, buffer, (data_len - excess_len));
//   if (result == -1) { return -errno; }
//
//
// //     parse_dp_header(buf, NULL, &recvlen);
// //     if (recvlen == -1) {
// //         fprintf(stderr, "out of sync with sciond\n");
// //         exit(1);
// //     }
// //     int reallen = recvlen > buflen ? buflen : recvlen;
//   //if (recvlen < 0) {
//   //    DEBUG("error while receiving header from sciond: %s\n", strerror(errno));
//   //    return;
//   //}
// }

// void PathManager::getPaths(double timeout)
// {
//     int buflen = (MAX_PATH_LEN + 15) * MAX_TOTAL_PATHS;
//     int recvlen;
//     uint8_t buf[buflen];
//
//     memset(buf, 0, buflen);
//
//     // Get local address first
//     if (mLocalAddr.isd_as == 0) {
//         queryLocalAddress();
//     }
//
//     prunePaths();
//     int numPaths = mPaths.size() - mInvalid;
//
//     if (timeout > 0.0) {
//         struct timeval t;
//         t.tv_sec = (size_t)floor(timeout);
//         t.tv_usec = (size_t)((timeout - floor(timeout)) * 1000000);
//         setsockopt(mDaemonSocket, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
//     }
//
//     // Now get paths for remote address(es)
//     std::vector<Path *> candidates;
//     memset(buf, 0, buflen);
//     *(uint32_t *)(buf + 1) = htonl(mDstAddr.isd_as);
//     send_dp_header(mDaemonSocket, NULL, 5);
//     send_all(mDaemonSocket, buf, 5);
//
//     memset(buf, 0, buflen);
//     recvlen = recv_all(mDaemonSocket, buf, DP_HEADER_LEN);
//     if (recvlen < 0) {
//         DEBUG("error while receiving header from sciond: %s\n", strerror(errno));
//         return;
//     }
//     parse_dp_header(buf, NULL, &recvlen);
//     if (recvlen == -1) {
//         fprintf(stderr, "out of sync with sciond\n");
//         exit(1);
//     }
//     int reallen = recvlen > buflen ? buflen : recvlen;
//     reallen = recv_all(mDaemonSocket, buf, reallen);
//     if (reallen > 0) {
//         DEBUG("%d byte response from daemon\n", reallen);
//         int offset = 0;
//         while (offset < reallen &&
//                 numPaths + candidates.size() < MAX_TOTAL_PATHS) {
//             uint8_t *ptr = buf + offset;
//             int pathLen = checkPath(ptr, reallen - offset, candidates);
//             if (pathLen < 0)
//                 break;
//             offset += pathLen;
//         }
//     }
//     insertPaths(candidates);
//     DEBUG("total %lu paths\n", mPaths.size() - mInvalid);
//
//     // If sciond sent excess data, consume it to sync state
//     if (reallen < recvlen) {
//         int remaining = recvlen - reallen;
//         while (remaining > 0) {
//             int read = recv(mDaemonSocket, buf, buflen, 0);
//             if (read < 0)
//                 break;
//             remaining -= read;
//         }
//     }
//
// Checks that the path is different from existing paths, doesnt use the same
// interfaces and is valid.
// int PathManager::checkPath(uint8_t *ptr, int len, std::vector<Path *> &candidates)
// {
//     bool add = true;
//     int pathLen = *ptr * 8;
//     if (pathLen + 1 > len)
//         return -1;
//     uint8_t addr_type = *(ptr + 1 + pathLen);
//     int addr_len = get_addr_len(addr_type);
//     // TODO: IPv6 (once sciond supports it)
//     int interfaceOffset = 1 + pathLen + 1 + addr_len + 2 + 2;
//     int interfaceCount = *(ptr + interfaceOffset);
//     if (interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN > len)
//         return -1;
//     for (size_t j = 0; j < mPaths.size(); j++) {
//         if (mPaths[j] &&
//                 mPaths[j]->isSamePath(ptr + 1, pathLen)) {
//             add = false;
//             break;
//         }
//     }
//     for (size_t j = 0; j < candidates.size(); j++) {
//         if (candidates[j]->usesSameInterfaces(ptr + interfaceOffset + 1, interfaceCount)) {
//             add = false;
//             break;
//         }
//     }
//     if (add) {
//         Path *p = createPath(mDstAddr, ptr, 0);
//         if (mPolicy.validate(p))
//             candidates.push_back(p);
//         else
//             delete p;
//     }
//     return interfaceOffset + 1 + interfaceCount * IF_TOTAL_LEN;
// }
