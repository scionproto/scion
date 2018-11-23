#!/bin/bash

# Wrapper to run integration binaries.

PROG=$1
shift

log() {
    echo "$(date -u --rfc-3339=ns) $@" 1>&2
}

set -o pipefail

"$PROG" "$@" |& while read line; do log $line; done
