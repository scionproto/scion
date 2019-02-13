#!/bin/bash

BASE="discovery/v1"
STATIC="static"
DYNAMIC="dynamic"
FULL="full.json"
ENDHOST="endhost.json"

ds_entry=$2
if [ -z "$2" ]; then
    ds_entry=1
fi

# Setup file structure.
temp_dir=$( mktemp -d )
printf "Created temp dir: $temp_dir\n"
mkdir -p "$temp_dir/$BASE/$STATIC"
mkdir -p "$temp_dir/$BASE/$DYNAMIC"
cat $1 | tee $temp_dir/$BASE/{$STATIC,$DYNAMIC}/{$FULL,$ENDHOST} > /dev/null

count=$( jq -r '.DiscoveryService | length' $1 )
printf "Using entry $ds_entry out of $count\n"

laddr=$( jq -r '.DiscoveryService[].Addrs.IPv4.Public.Addr' $1 | sed -n "${ds_entry}p" )
port=$( jq -r '.DiscoveryService[].Addrs.IPv4.Public.L4Port' $1 | sed -n "${ds_entry}p" )

# Start http server that serves the files in the temp directory.
cd $temp_dir
python3 -m http.server $port --bind $laddr 
