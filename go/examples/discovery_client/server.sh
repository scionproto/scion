#!/bin/bash

BASE="discovery/v1"
STATIC="static"
DYNAMIC="dynamic"
FULL="full.json"
REDUCED="reduced.json"

# Setup file structure.
temp_dir=$( mktemp -d )
printf "Created temp dir: $temp_dir\n"
mkdir -p "$temp_dir/$BASE/$STATIC"
mkdir -p "$temp_dir/$BASE/$DYNAMIC"
cat $1 | tee $temp_dir/$BASE/{$STATIC,$DYNAMIC}/{$FULL,$REDUCED} > /dev/null

# Start http server.
cd $temp_dir
python3 -m http.server $2
