#!/bin/bash

cntrs="$(docker ps -aq)"
[ -n "$cntrs" ] && { echo "Remove leftover containers: $cntrs"; docker rm -f "$cntrs"; }

echo "Try to remove leftover networks"
docker network prune -f
echo "Try to remove leftover volumes"
docker volume prune -f
