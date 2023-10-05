#!/bin/bash
# Copyright 2016 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -f

REV_BRS="*br1-ff00_0_110-3 *br2-ff00_0_222-2 *br1-ff00_0_111-2 *br1-ff00_0_111-3 *br1-ff00_0_131-2 "\
"*br2-ff00_0_220-2 *br2-ff00_0_210-4 *br2-ff00_0_212-1"

for br in $REV_BRS; do
    if ! ./scion.sh mstatus "$br"; then
        echo "${br} does not exist. Abort."
        exit 1
    fi
done

# Bring down routers.
echo "Revocation test"
echo "Stopping routers and waiting for 4s."
./scion.sh mstop $REV_BRS
if [ $? -ne 0 ]; then
    echo "Failed stopping routers."
    exit 1
fi
sleep 4

if [ -f gen/scion-dc.yml ]; then
    DOCKER_ARGS="-d"
fi

# Do another round of e2e test with retries
echo "Testing connectivity between all the hosts (with retries)."
bin/end2end_integration $DOCKER_ARGS -log.console info -attempts 15 -subset 1-ff00:0:131#2-ff00:0:222
exit $?
