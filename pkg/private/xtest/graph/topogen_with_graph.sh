#!/bin/bash

topogen="$1"
# $2 and $3 are other files passed by topogen's py_binary to the Bazel rule running this script.
topology="$4"
ifids="$5"
out="$6"

tmpdir=$(mktemp -d)

"$topogen" -c="$topology" -t -o="$tmpdir"

for dir in $tmpdir/*; do
  if [ -f "$dir/topology.json" ]; then
    DIR_NAME=$(basename $dir)
    mv "$dir/topology.json" "$out/${DIR_NAME}.json"
  fi
done

CORRECT_YAML="$ifids"
WRONG_YAML="$tmpdir/ifids.yml"

declare -A wrong_local wrong_remote
# The "|| [[ -n "$br1" ]]" keeps the last line when the file has no trailing newline
while IFS=' ' read -r br1 num1 br2 num2 || [[ -n "$br1" ]]; do
  [[ "$br1" == br* ]] || continue
  wrong_local["$br1 $br2"]="${num1%:}"   # num1 is a YAML key, so it ends with a colon we drop
  wrong_remote["$br1 $br2"]="$num2"
done < "$WRONG_YAML"

while IFS=' ' read -r br1 num1 br2 num2 || [[ -n "$br1" ]]; do
  [[ "$br1" == br* ]] || continue
  num1="${num1%:}"
  num1_wrong="${wrong_local["$br1 $br2"]}"
  num2_wrong="${wrong_remote["$br1 $br2"]}"

  # br1 names the local AS's border router, so rewrite only that AS's file (e.g.
  # br4-ff00_0_410-1 -> $out/ASff00_0_410.json)
  ia="${br1#br}"; ia="${ia%-*}"      # 4-ff00_0_410
  json_file="$out/AS${ia#*-}.json"   # ASff00_0_410.json

  sed -i "s/\"$num1_wrong\":/\"$num1\":/g" "$json_file"
  sed -i "s/\"remote_interface_id\": $num2_wrong\b/\"remote_interface_id\": $num2/g" "$json_file"
done < "$CORRECT_YAML"
