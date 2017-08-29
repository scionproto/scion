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

set -o pipefail

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

check_hidden_path_exists() {
    if cat ./gen/as_list.yml | grep "Hidden-AS" >/dev/null; then
        return 0
    fi
    return 1
}

if ! check_hidden_path_exists; then
    log "hidden path does not exist. Skipping hidden path test."
    exit 0
fi

export PYTHONPATH=python/:.
python/integration/end2end_test.py -l ERROR --hidden-path True
result=$?
if [ ${result} -ne 0 ]; then
    log "hidden path test failed. (${result})"
fi
exit ${result}
