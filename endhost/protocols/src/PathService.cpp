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
extern "C" {
#include "utils.h"
}
#include "PathService.h"

PathService::~PathService()
{
  // Close the socket
  if (close(m_daemon_sockfd) != 0) {
    std::cerr << "Error sciond socket close: " << std::strerror(errno) << "\n";
  }
}


std::unique_ptr<PathService> PathService::create(uint32_t dest_isd_as,
                                                 const char* daemon_addr,
                                                 int* error)
{
  // Create a new service instance and initialize it
  std::unique_ptr<PathService> service{new PathService(dest_isd_as)};

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


// Pruning only removes records with invalid policies. That cleanup should be
// handled when the policy changes, not here.
//
// It's possible that unused paths will block inserting new paths. A LRU cache
// or expiry cache could be used to ensure fresh inserts.
int PathService::refresh_paths(std::set<int> &new_keys)
{
  // FIXME(jsmith): The upper bound is an estimation, calculate accurately.
  const int buffer_len = 250 * m_max_paths;
  uint8_t buffer[buffer_len];

  // Get the path data from the SCION daemon
  m_daemon_rw_mutex.Lock();
  int path_data_len = lookup_paths(m_dest_isd_as, buffer, buffer_len);
  m_daemon_rw_mutex.Unlock();
  if (path_data_len < 0) { return path_data_len; }

  // Parse and insert the records
  int bytes_used = 0;
  m_records_mutex.Lock();
  do {
    std::unique_ptr<PathRecord> record{new PathRecord()};
    bytes_used = parse_path_record(buffer, path_data_len, record.get());

    if (bytes_used != 0 && m_policy.is_valid(*record)) {
      // Parse was successful & the path satisfies the policy.
      bool updated = false;
      int record_key = insert_record(record, updated);

      if (record_key != -1 && !updated) {  // New record inserted
        // Update the set of new keys
        new_keys.insert(record_key);
      } else {
        // It either failed & will be cleaned up, or was an update and is now
        // held in the local store.
      }
    } else {
      // The record is destroyed
    }
    // Update remaining bytes
    path_data_len -= bytes_used;
  } while (bytes_used != 0 && path_data_len != 0);
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
