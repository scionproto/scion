#!/bin/bash

set -e

usermod -u ${SCION_UID:?} scion
groupmod -g ${DOCKER_GID:?} docker

SU_EXEC_USERSPEC=scion /sbin/su-exec "$@"
