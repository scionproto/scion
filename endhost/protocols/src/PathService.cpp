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

#include <list>
#include <set>
#include <cstring>
#include <cmath>
#include <cassert>
#include <memory>
#include <iostream>

#include "util.h"
#include "sciondlib.h"
#include "utils.h"
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
  // Create a new service instance and initialize it
  std::unique_ptr<PathService> service{new PathService()};

  // Set the timeout and check the error
  *error = service->set_timeout(0.0);
  if (*error != 0) {
    return nullptr;
  }

  // Connect to daemon and handle any errors
  int result = daemon_connect(daemon_addr);
  if (result >= 0) {
    service->m_daemon_sockfd = result;
  } else {
    *error = result;
    service = nullptr;  // Free the memory
  }
  return service;
}


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


int PathService::lookup_paths(uint32_t isd_as, uint8_t* buffer, int buffer_len)
{
  assert(buffer_len > DP_HEADER_LEN);

  // Send the path request
  int data_len = write_path_request(buffer, isd_as);
  int result = send_all(m_daemon_sockfd, buffer, data_len);
  if (result == -1) { return -errno; }

  // Read  and parse the communication header
  result = recv_all(m_daemon_sockfd, buffer, DP_HEADER_LEN);
  if (result == -1) { return -errno; }

  // Determine how much data we should expect
  parse_dp_header(buffer, /*addr_len=*/nullptr, &data_len);
  if (data_len == -1) {
    return -EAGAIN;  // Possible desynchronization.
  }

  // Calculate the unwanted excess in the response
  int excess_len = (data_len > buffer_len) ? (data_len - buffer_len) : 0;

  // Read the response
  result = recv_all(m_daemon_sockfd, buffer, (data_len - excess_len));
  return (result == -1) ? -errno : result;
}


int PathService::refresh_paths(uint32_t isd_as)
{
  // FIXME(jsmith): The upper bound is an estimation, calculate accurately.
  const int buffer_len = 250 * m_max_paths;
  uint8_t buffer[buffer_len];

  // Get the path data from the SCION daemon
  m_daemon_rw_mutex.Lock();
  int path_data_len = lookup_paths(isd_as, buffer, buffer_len);
  m_daemon_rw_mutex.Unlock();
  if (path_data_len < 0) { return path_data_len; }

  // Parse the records
  int bytes_used = 0;
  std::list<std::unique_ptr<PathRecord>> records;
  do {
    std::unique_ptr<PathRecord> record{new PathRecord()};
    bytes_used = parse_path_record(buffer, path_data_len, record.get());

    if (bytes_used != 0 && m_policy.is_valid(*record)) {
      // Parse was successful & the path satisfies the policy.
      records.push_back(std::move(record));
    } else {
      // The record is destroyed
    }
    // Update remaining bytes
    path_data_len -= bytes_used;
  } while (bytes_used != 0 && path_data_len != 0);

  // Update the existing records and insert the new ones
  m_records_mutex.Lock();
  std::set<int> new_keys;  // TODO(jsmith): Make param
  // Attempt to insert the new records. We do this before pruning to allow
  // overwriting expired records while maintaining their keys.
  // TODO(jsmith): Derive a key from the record (e.g. hash) to improve
  attempt_inserts(records, new_keys);
  prune_records();  // Free space by removing any expired records
  if (!records.empty()) {
    attempt_inserts(records, new_keys);
  }
  m_records_mutex.Unlock();

  return 0;  // Anything that wasnt inserted is cleanup with the list
}


int PathService::insert_record(std::unique_ptr<PathRecord> &record,
                               bool &updated)
{
  int record_id = 0;
  // Check if a record with the same interfaces already exists
  for (const auto& entry : m_records) {
    if (has_same_interfaces(record.get(), entry.second.get()) == 1) {
      record_id = entry.first;
      break;
    }
  }
  if (record_id != 0) {
    // Flag that it's an update
    updated = true;
    // Perform an update by delete the old record to make space for the new
    destroy_spath_record(m_records[record_id].get());
  } else {
    // Flag that it would be an insertion
    updated = false;
    // Ensure enough space for the insertion
    if (m_records.size() == m_max_paths) {
      return -1;
    }
    // Select a new record id
    record_id = m_next_record_id;
    m_next_record_id += 1;
  }
  // Insert the new record
  m_records[record_id] = std::move(record);
  return record_id;
}


void PathService::attempt_inserts(
    std::list<std::unique_ptr<PathRecord> > &records,
    std::set<int> &new_keys)
{
  auto iter = records.begin();
  while (iter != records.end()) {
    bool updated = false;
    int record_key = insert_record(*iter, updated);

    if (record_key != -1) {  // Record inserted
      // Remove it from the list and update the set of new keys
      iter = records.erase(iter);
      if (!updated) {
        new_keys.insert(record_key);
      }
    } else {
      ++iter;
    }
  }
}


// Prune based on both policy validity, as policies may change, and expiration
// timestamp. Otherwise, if an invalid path is not being used, we will never
// get an SCMP message and the path with never be forcibly removed.
// A timed cache would perhaps be a more appropriate structure.
void PathService::prune_records()
{
  auto iter = m_records.begin();
  while (iter != m_records.end()) {
    if (m_policy.is_valid(*(iter->second))) {  // TODO(jsmith): Check expiration
      ++iter;
    } else {
      iter = m_records.erase(iter);
    }
  }
}
// void PathManager::prunePaths()
// {
//     for (size_t i = 0; i < mPaths.size(); i++) {
//         Path *p = mPaths[i];
//         if (p && (!p->isValid() || !mPolicy.validate(p))) {
//             DEBUG("path %lu not valid\n", i);
//             mPaths[i] = NULL;
//             delete p;
//             mInvalid++;
//         }
//     }
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
//
//
// Insert new paths into the path list by first filling any empty positions
// then appending to the end of the path list.
// void PathManager::insertPaths(std::vector<Path *> &candidates)
// {
//     if (candidates.empty())
//         return;
//
//     for (size_t i = 0; i < mPaths.size(); i++) {
//         if (mPaths[i])
//             continue;
//         Path *p = candidates.front();
//         candidates.erase(candidates.begin());
//         mPaths[i] = p;
//         p->setIndex(i);
//         mInvalid--;
//         if (candidates.empty())
//             break;
//     }
//     for (size_t i = 0; i < candidates.size(); i++) {
//         Path *p = candidates[i];
//         int index = mPaths.size();
//         mPaths.push_back(p);
//         p->setIndex(index);
//     }
// }
//
// int PathManager::insertOnePath(Path *p)
// {
//     for (size_t i = 0; i < mPaths.size(); i++) {
//         if (mPaths[i])
//             continue;
//         mPaths[i] = p;
//         p->setIndex(i);
//         mInvalid--;
//         return i;
//     }
//     int index = mPaths.size();
//     mPaths.push_back(p);
//     p->setIndex(index);
//     return index;
// }
