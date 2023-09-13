#!/bin/bash

echo "~~~ Cleaning up any leftovers"
cntrs="$(docker ps -aq | grep -v -f <(docker ps -q --filter "name=go-module-proxy" --filter "name=bazel-remote-cache"))"
[ -n "$cntrs" ] && { echo "Remove leftover containers..."; docker rm -f $cntrs; }
echo "Remove leftover networks"
docker network prune -f
echo "Remove leftover volumes"
docker volume prune -f

rm -rf bazel-testlogs logs/* traces gen gen-cache /tmp/test-artifacts test-out.tar.gz
