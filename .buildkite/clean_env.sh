#!/bin/bash

cntrs="$(docker ps -aq)"
[ -n "$cntrs" ] && { echo "Remove left over containers: $cntrs"; docker rm -f "$cntrs"; }

echo "Try to remove left over networks"
docker network prune -f
