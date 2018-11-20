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

run() {
    local test="${1:?}"
    shift
    log "$test: starting"
    time "$@"
    local result=$?
    if [ $result -eq 0 ]; then
        log "$test: success"
    else
        log "$test: failure"
    fi
    return $result
}

is_docker_be() {
    [ -f gen/scion-dc.yml ]
}

is_running_in_docker() {
    cut -d: -f 3 /proc/1/cgroup | grep -q '^/docker/'
}

usage() {
    echo "Usage: $0: [-b brs]"
    exit 1
}

opts() {
    while getopts ":b:" opt; do
        case "$opt" in
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
    # Set if docker backend is used
    is_docker_be && DOCKER_ARGS="-d"
}

export PYTHONPATH=python/:.
