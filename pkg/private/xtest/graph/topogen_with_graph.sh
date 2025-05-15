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

MAPPING_FILE=$(mktemp)

exec 3< "$WRONG_YAML"

mapfile -t lines < "$CORRECT_YAML"
mapfile -t -u 3 wrong_lines

for i in "${!lines[@]}"; do
  IFS=' ' read -r br1 num1 br2 num2 <<< "${lines[i]}"
  IFS=' ' read -r br1_wrong num1_wrong br2_wrong num2_wrong <<< "${wrong_lines[i]}"

  if [[ -n "$br1" && -n "$num1" && -n "$br2" && -n "$num2" ]]; then
    # No need to add num1 as it'll create a duplicate: there are entries for both directions.
    # Also, num1 contains a colon after the number.
    echo "$num2_wrong $num2" >> "$MAPPING_FILE"
  fi
done

exec 3<&-

for json_file in $out/*.json; do
  while read -r wrong correct; do
    # This works in our case since topogen -t will generate ifIDs only in 10000-30000 range.
    # The only other numbers in topology.json files are: AS IDs (3-digit numbers),
    # dispatched ports (31000-32767), and MTU (topogen sets it to 1472 by default),
    # so this script will change only ifIDs.
    sed -i "s/\\b$wrong\\b/$correct/g" "$json_file"
  done < "$MAPPING_FILE"
done
