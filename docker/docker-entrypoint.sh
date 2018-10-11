#!/bin/bash

set -e

usermod -u $SCION_UID scion
groupmod -g $DOCKER_GID docker

su scion -l -c "$@"
