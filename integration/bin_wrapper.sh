#!/bin/bash

# Wrapper to run integration binaries.

PROG=$1
shift

log() {
    echo "$(date -u +"%F %T.%6N%z") $@" 1>&2
}

set -o pipefail

[ -n "$IA" ] && echo "Listening ia=$IA"

log "bin_wrapper: Starting $PROG $@"

"$PROG" "$@" |& while read line; do log $line; done
exit_status=$?

log "bin_wrapper: Stopped"

exit $exit_status
