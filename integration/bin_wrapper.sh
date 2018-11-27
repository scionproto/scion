#!/bin/bash

# Wrapper to run integration binaries.

PROG=$1
shift

log() {
    echo "$(date -u +"%F %T.%6N%z") $@" 1>&2
}

set -o pipefail

"$PROG" "$@" |& while read line; do log $line; done
