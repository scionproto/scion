#!/bin/bash

# For caching docker builds in circleci
# Expects to be run in the root directory of a scion repo checkout

CACHEDIR=~/cache
DOCKERCACHE=$CACHEDIR/scion-docker.tar.gz
BUILDDIR=docker/_build

cmd_save() {
    echo "====> Docker image: saving"
    time docker save scion:latest | gzip -1 > "$DOCKERCACHE"
    echo "====> Docker image: saved ($(get_size "$DOCKERCACHE"))"
}

cmd_restore() {
    if [ ! -e "$DOCKERCACHE" ]; then
        echo "====> Docker image: nothing to restore"
        return 0
    fi
    echo "====> Docker image: restoring ($(get_size "$DOCKERCACHE"))"
    time gunzip -c "$DOCKERCACHE" | docker load
    echo "====> Docker image: restored"
}

get_size() {
    du -hs "${1:?}" | awk '{print $1}'
}

cmd_clean() {
    rm -r "${CACHEDIR:?}"
}

CMD="$1"
shift

case "$CMD" in
    save)
        cmd_save "$@"
        ;;
    restore)
        cmd_restore "$@"
        ;;
    clean)
        cmd_clean "$@"
        ;;
    *)
        echo "Error: unknown command \"$1\""
        exit 1
        ;;
esac
