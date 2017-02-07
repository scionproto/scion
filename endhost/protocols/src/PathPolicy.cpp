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

#include "PathPolicy.h"

#include "sciondlib.h"


void PathPolicy::whitelist_isds(const std::vector<uint16_t> &isds)
{
  m_policy_mutex.Lock();
  if (isds.empty()) {
    m_isd_whitelist.clear();
  } else {
    m_isd_whitelist.insert(isds.begin(), isds.end());
  }
  m_policy_mutex.Unlock();
}


// Currently the only applicable check is the ISD white list
bool PathPolicy::validate(const spath_record_t &record) const
{
  m_policy_mutex.Lock();
  bool is_valid = m_isd_whitelist.empty() || is_whitelisted(record);
  m_policy_mutex.Unlock();

  return is_valid;
}


bool PathPolicy::is_whitelisted(const spath_record_t &record) const
{
  for (int i = 0; i < record.interface_count; ++i) {
    uint16_t isd = ISD(record.interfaces[i].isd_as);
    if (m_isd_whitelist.find(isd) == m_isd_whitelist.end()) {
      return false;
    }
  }
  return true;
}
