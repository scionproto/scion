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

#ifndef PATH_POLICY_H
#define PATH_POLICY_H

#include <set>
#include <vector>

#include "SCIONDefines.h"

class Path;

class PathPolicy {
public:
    PathPolicy();
    ~PathPolicy();

    void setISDWhitelist(std::vector<uint16_t> &isds);

    bool validate(Path *p);

protected:
    bool isWhitelisted(Path *p);

    std::set<uint16_t> mWhitelist;
    std::vector<uint16_t> mAvoidISDs;
    std::vector<uint32_t> mAvoidADs;
};

#endif
