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

REV_BRS="*br1-ff00_0_110-3 *br2-ff00_0_222-2 *br1-ff00_0_111-2 *br1-ff00_0_111-3 *br1-ff00_0_131-2"
REV_BRS="$REV_BRS *br2-ff00_0_220-2 *br2-ff00_0_210-4 *br2-ff00_0_212-1"

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

usage() {
    echo "Usage: $0: [-b brs] [-d ctr_name]"
    exit 1
}

opts() {
    while getopts ":b:d:" opt; do
        case "$opt" in
            d)
                CONTAINER="$OPTARG"
                docker inspect "$CONTAINER" &>/dev/null || \
                    { echo "Container $CONTAINER not found, aborting!"; exit 1; }
                ;;
            b)
                REV_BRS="$OPTARG"
                ;;
            \?)
                echo "Invalid option: -$OPTARG" >&2
                usage
                ;;
            :)
                echo "Option -$OPTARG requires an argument." >&2
                usage
                ;;
            *)
                usage
                ;;
        esac
    done
}

export PYTHONPATH=python/:.
