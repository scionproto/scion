#!/bin/bash

set -e

usermod -u $SCION_ID scion
groupmod -g $DOCKER_ID docker

su scion -c "$@"
