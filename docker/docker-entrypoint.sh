#!/bin/bash

set -e

# Change the current uid to SCION_UID, gid to SCION_GID and fix file permissions
chown -R ${SCION_UID:?}:${SCION_GID:?} ~scion
usermod -u ${SCION_UID:?} scion
groupmod -g ${SCION_GID:?} scion
# Change docker gid to DOCKER_GID
groupmod -g ${DOCKER_GID:?} docker

SU_EXEC_USERSPEC=scion /sbin/su-exec bash -l "$@"
