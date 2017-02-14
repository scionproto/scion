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

#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <array>
#include <cassert>
#include <cmath>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <set>

#include "util.h"
#include "sciondlib.h"
extern "C" {
#include "utils.h"
}
#include "PathService.h"
#include "UnixSocket.h"
#include "MockUnixSocket.h"


template<typename T>
std::unique_ptr<PathService<T>> PathService<T>::create(uint32_t dest_isd_as,
                                                 const char* daemon_addr,
                                                 int &error)
{
  // Create a new service instance and initialize it
  std::unique_ptr<PathService<T>> service{new PathService<T>(dest_isd_as)};

  // Set the timeout and check the error
  error = service->set_timeout(0.0);
  if (error != 0) {
    return nullptr;
  }

  // Connect to daemon and handle any errors
  int result = service->m_daemon_sock.connect(daemon_addr);
  if (result == -1) {
    error = -errno;
    return nullptr;
  }

  return service;
}


template<typename T>
int PathService<T>::set_timeout(double timeout)
{
  struct timeval timeout_val;
  // Separate the timeout into seconds and microseconds
  // FIXME(jsmith): Narrowing cast concerns here?
  timeout_val.tv_sec = time_t(std::trunc(timeout));
  timeout_val.tv_usec = suseconds_t((timeout - std::trunc(timeout)) * 1e6);

  int result = m_daemon_sock.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &timeout_val,
                                        sizeof(timeout_val));
  return (result == -1) ? -errno : 0;
}


template<typename T>
int PathService<T>::lookup_paths(std::vector<uint8_t> &buffer)
{
  // Resize the buffer to hold the path request
  buffer.resize(PATH_REQUEST_LEN);

  // Send the path request
  int data_len = write_path_request(buffer.data(), m_dest_isd_as);
  assert(data_len == PATH_REQUEST_LEN);
  int result = m_daemon_sock.send_all(buffer.data(), buffer.size());
  if (result == -1) { return -errno; }

  // Read and parse the communication header
  result = m_daemon_sock.recv_all(buffer.data(), DP_HEADER_LEN);
  if (result == -1) { return -errno; }

  // Determine how much data we should expect
  parse_dp_header(buffer.data(), /*addr_len=*/nullptr, &data_len);
  if (data_len == -1) {
    return -EAGAIN;  // Possible desynchronization.
  }

  // Read the full response
  buffer.resize(data_len);
  result = m_daemon_sock.recv_all(buffer.data(), data_len);
  assert(result == data_len);
  return (result == -1) ? -errno : result;
}


// Pruning only removes records with invalid policies. That cleanup should be
// handled when the policy changes, not here.
//
// It's possible that unused paths will block inserting new paths. A LRU cache
// or expiry cache could be used to ensure fresh inserts.
template<typename T>
int PathService<T>::refresh_paths(std::set<int> &new_keys)
{
  // Get the path data from the SCION daemon
  std::vector<uint8_t> buffer;
  m_daemon_rw_mutex.Lock();
  int path_data_len = lookup_paths(buffer);
  m_daemon_rw_mutex.Unlock();
  if (path_data_len < 0) { return path_data_len; }

  // Parse and insert the records
  int bytes_used = 0, offset = 0;
  m_records_mutex.Lock();
  // Parse records from the buffer until either insufficent data exists for a
  // parse or all the data has been consumed.
  do {
    std::unique_ptr<PathRecord> record{new PathRecord()};
    bytes_used = parse_path_record(&buffer[offset], path_data_len,
                                   record.get());
    offset += bytes_used;

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


template<typename T>
int PathService<T>::insert_record(std::unique_ptr<PathRecord> &record,
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
  } else {
    // Flag that it would be an addition
    updated = false;
    // Ensure enough space for the addition
    if (m_records.size() == m_max_paths) {
      return -1;
    }
    // Select a new record id
    record_id = m_next_record_id;
    m_next_record_id += 1;
  }
  // Insert the new record
  // If it's a replacement the loss of previous unique_ptr should do any
  // necessary cleanup
  m_records[record_id] = std::move(record);
  return record_id;
}


// TODO(jsmith): Prune based on both policy validity as well as have them
// expire. Otherwise, if an invalid path is not being used, we will never
// get an SCMP message and the path with never be forcibly removed.
// A timed cache would perhaps be a more appropriate structure.
template<typename T>
int PathService<T>::prune_records()
{
  int num_removed = 0;
  auto iter = m_records.begin();
  while (iter != m_records.end()) {
    if (m_policy.is_valid(*(iter->second))) {
      ++iter;
    } else {
      iter = m_records.erase(iter);
      num_removed += 1;
    }
  }
  return num_removed;
}


// Declare the necessary templates
template class PathService<UnixSocket>;
template class PathService<MockUnixSocket>;
