#!/bin/bash

set -e

docker build -f docker/ci/build/Dockerfile -t scion_base_build:latest .
docker run -v "/home/luke/go/src/github.com/scionproto/scion/:/data" --rm  -it --entrypoint bash scion_base_build:latest
# make -s GODEPS_SKIP=1 GOGEN_SKIP=1 all setcap && bazel clean