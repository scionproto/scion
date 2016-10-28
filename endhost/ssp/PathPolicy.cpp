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

#include "Path.h"
#include "PathPolicy.h"

PathPolicy::PathPolicy()
{
}

PathPolicy::~PathPolicy()
{
}

void PathPolicy::setISDWhitelist(std::vector<uint16_t> &isds)
{
    if (isds.empty())
        mWhitelist.clear();

    for (size_t i = 0; i < isds.size(); i++)
        mWhitelist.insert(isds[i]);
}

bool PathPolicy::validate(Path *p)
{
    if (!mWhitelist.empty() && !isWhitelisted(p))
        goto FAIL;

    return true;
FAIL:
    DEBUG("path %d invalid\n", p->getIndex());
    return false;
}

bool PathPolicy::isWhitelisted(Path *p)
{
    std::vector<SCIONInterface> &ifs = p->getInterfaces();
    for (size_t i = 0; i < ifs.size(); i++) {
        SCIONInterface sif = ifs[i];
        if (mWhitelist.find(sif.isd) == mWhitelist.end())
            return false;
    }
    return true;
}
