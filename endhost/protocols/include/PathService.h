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

/* Provides an interface to the SCION daemon for fetching and caching path
 * records as well as a wrapper around the path record struct to allow for
 * easy cleanup.
 */
#ifndef PATH_SERVICE_H_
#define PATH_SERVICE_H_

#include <map>
#include <memory>
#include <set>
#include <list>

#include "sciondlib.h"
#include "Mutex.h"
#include "MutexScion.h"
#include "PathPolicy.h"
#include "UnixSocket.h"
#include "gtest/gtest_prod.h"

/* A thin wrapper around the C path record structure to handle deallocating
 * the internal resources.
 */
class PathRecord: public spath_record_t {
public:
  PathRecord() = default;
  ~PathRecord() { destroy_spath_record(this); }

private:
  // Unsuported default operations
  PathRecord(const PathRecord&) = delete;
  PathRecord& operator=(const PathRecord&) = delete;
  PathRecord(PathRecord&&) = delete;
  PathRecord& operator=(PathRecord&&) = delete;
};


/* SCION daemon interface and path store.
 *
 * This service is responsible for fetching and verifying path data. Paths are
 * referenced by their associated keys which allows for updating the details of
 * a path without invalidating the reference.
 *
 * TODO(jsmith): Paths when returned are returned by copy to avoid fine-grained
 * locking.
 */
template<typename T = UnixSocket>
class PathService {
public:
  ~PathService() = default;

  /* Create a new instance of the path service.
   *
   * @param daemon_addr The AF_UNIX address of the SCION daemon.
   * @param[out] error On success, 'error' is set to zero. Otherwise it is set
   *                   to a negative Linux system error code pertaining to the
   *                   error.
   */
  static std::unique_ptr<PathService> create(uint32_t dest_isd_as,
                                             const char* daemon_addr,
                                             int &error);


  /* Sets the receive timeout in seconds for queries to the SCION daemon.
   *
   * On success, zero is returned. On error a negative Linux system error code
   * as defined in setsockopt is returned.
   */
  int set_timeout(double timeout);


  /* Query the SCION daemon for paths to previously specified AS and update the
   * local record cache.
   *
   * On success, zero is returned and the keys to any new (as opposed to
   * updated) records are inserted into new_keys. On error a negative system
   * error number is returned.
   */
  int refresh_paths(std::set<int> &new_keys)
    EXCLUDES(m_records_mutex, m_daemon_rw_mutex);

  // TODO(jsmith): Verify that the record complies to the policy and inserts it
  // int add_record();

private:
  PathService(uint32_t isd_as)
    : m_dest_isd_as{isd_as}
  { };


  /* Query the SCION daemon for paths to the isd_as.
   *
   * On success, the result is loaded into buffer (truncated at buffer_len
   * bytes) and the amount of data written to the buffer is returned.
   * Otherwise, a negative system error code is returned.
   */
  int lookup_paths(std::vector<uint8_t> &buffer) REQUIRES(m_daemon_rw_mutex);


  /* Add a record to the path service.
   *
   * An existing record with the same interfaces is replaced by the new record,
   * while maintinging the record's key.
   *
   * Returns the identifier of the record where the insertion or replacement
   * took place, or -1 if the insertion would excede the number of allowed
   * records.
   *
   * @param[out] updated True if a record was updated, false otherwise.
   * @param[in,out] record The record to be inserted. A successful insert will
   *                       claim the unique_ptr.
   */
  int insert_record(std::unique_ptr<PathRecord> &record, bool &updated)
    REQUIRES(m_records_mutex);


  // Removes non-conformant records
  void prune_records() REQUIRES(m_records_mutex);


  const uint32_t m_dest_isd_as;

  // SCION daemon socket
  T m_daemon_sock;

  // Maxmimum number of record to cache
  const int m_max_paths{20};
  // The ID to be used to insert a record
  int m_next_record_id GUARDED_BY(m_records_mutex) {1};
  // Cache of the path records
  std::map<int, std::unique_ptr<PathRecord> > m_records
    GUARDED_BY(m_records_mutex);

  // Associated policy for the records
  PathPolicy m_policy;

  // Mutexes
  Mutex m_daemon_rw_mutex; // For read/write operations on the socket
  Mutex m_records_mutex;   // For access to the records

  // Unsuported default operations
  PathService(const PathService&) = delete;
  PathService& operator=(const PathService&) = delete;
  PathService(PathService&&) = delete;
  PathService& operator=(PathService&&) = delete;

  // Tests
  FRIEND_TEST(PathServiceTest, GetsNewRecords);
};

#endif  // PATH_SERVICE_H_
