#!/bin/bash
# Copyright 2018 ETH Zurich
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

run_docker() {
    local cmd="$1"
    shift
    docker container exec $CONTAINER bash -lc "$cmd \"\$@\"" "/bin/bash" "$@"
}

run() {
    local test="${1:?}"
    shift
    log "$test: starting"
    if [ -z "$CONTAINER" ]; then
        time $@
    else
        time run_docker $@
    fi
    local result=$?
    if [ $result -eq 0 ]; then
        log "$test: success"
    else
        log "$test: failure"
    fi
    return $result
}

export -f run run_docker log
export PYTHONPATH=python/:.

# Check for docker flag and if the container is present
while test $# -gt 0; do
    case "$1" in
        -docker)
            shift
            CONTAINER=${1:-scion_ci}
            docker inspect "$CONTAINER" &>/dev/null || \
                { echo "Container $CONTAINER not found, aborting!"; exit 1; }
            shift
        ;;
        *)
            break
        ;;
    esac
done
