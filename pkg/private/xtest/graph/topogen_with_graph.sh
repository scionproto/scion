#!/bin/bash

topogen="$1"

# $2 and $3 belong to py_binary with topogen
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

while read -r line && read -r wrong_line <&3; do
  IFS=' ' read -r br1 num1 br2 num2 <<< "$line"
  IFS=' ' read -r br1_wrong num1_wrong br2_wrong num2_wrong <<< "$wrong_line"

  if [[ -n "$br1" && -n "$num1" && -n "$br2" && -n "$num2" ]]; then
    # no need to add num1 since it'll create a duplicate (with a colon after the number)
    echo "$num2_wrong $num2" >> "$MAPPING_FILE"
  fi
done < "$CORRECT_YAML"

exec 3<&-

for json_file in $out/*.json; do
  while read -r wrong correct; do
    sed -i "s/\\b$wrong\\b/$correct/g" "$json_file"
  done < "$MAPPING_FILE"
done
