/* Copyright 2016 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PATH_POLICY_H_
#define PATH_POLICY_H_

#include <set>
#include <vector>
#include <cstdint>

#include "sciondlib.h"


/* A policy for describing allowed SCION paths. Currently supports whitelisting
 * ISDs.
 */
class PathPolicy {
public:
  PathPolicy() = default;
  ~PathPolicy() = default;

  /* Adds the specified ISDs to the ISD whitelist.
   *
   * Supplying an empty list clears the ISD whitelist.
   */
  void whitelist_isds(const std::vector<uint16_t> &isds);

  /* Returns true if the path record is valid as per this path policy, false
   * otherwise.
   */
  bool validate(const spath_record_t &record) const;

private:
  /* Retuns true if every ISD traversed by the path referred to by record is
   * in the whitelist, and false otherwise.
   *
   * Note an empty whitelist will result in this method always returning false.
   */
  bool is_whitelisted(const spath_record_t &record) const;

  // If non-empty, all paths must only utilize ISDs in the whitelist.
  std::set<uint16_t> m_isd_whitelist;

  // Unsuported default operations
  PathPolicy(const PathPolicy&) = delete;
  PathPolicy& operator=(const PathPolicy&) = delete;
  PathPolicy(PathPolicy&&) = delete;
  PathPolicy& operator=(PathPolicy&&) = delete;
};

#endif
