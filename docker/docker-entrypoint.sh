#!/bin/bash

set -e

# Change the current uid to SCION_UID, gid to SCION_GID and fix file permissions
if [ $SCION_UID -ne $(id -u scion) ] || [ $SCION_GID -ne $(id -g scion) ]; then
    echo "Run chown on ~scion"
    chown -R ${SCION_UID:?}:${SCION_GID:?} ~scion
fi
if [ $SCION_UID -ne $(id -u scion) ]; then
    echo "Run usermod scion"
    usermod -u ${SCION_UID:?} scion
fi
if [ $SCION_GID -ne $(id -g scion) ]; then
    echo "Run groupmod scion"
    groupmod -g ${SCION_GID:?} scion
fi
if [ $DOCKER_GID -ne $(getent group docker | cut -f3 -d:) ]; then
    # Change docker gid to DOCKER_GID
    echo "Run groupmod docker"
    groupmod -g ${DOCKER_GID:?} docker
fi

SU_EXEC_USERSPEC=scion /sbin/su-exec bash -l "$@"
