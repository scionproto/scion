#!/bin/bash

cntrs="$(docker ps -aq)"
[ -n "$cntrs" ] && { echo "Remove leftover containers: $cntrs"; docker rm -f $cntrs; }

echo "Remove leftover networks"
docker network prune -f
echo "Remove leftover volumes"
docker volume prune -f
