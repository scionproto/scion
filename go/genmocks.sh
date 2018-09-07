#!/bin/bash

declare -a source_ifaces=(
    "lib/infra/common.go"
    "lib/pathdb/pathdb.go"
    "lib/snet/snetproxy/interface.go"
    "lib/snet/snetproxy/reconnecter.go"
    "lib/snet/snetproxy/io.go"
)

for iface in "${source_ifaces[@]}"
do
    folder=$(dirname "$iface")
    package=$(basename $folder)
    file=$(basename "$iface")
    gen_base="$folder/mock_$package"
    mkdir -p "$gen_base"
    mockgen -destination="$folder/mock_$package/mock_$file" -source="$iface"
done

declare -a lib_ifaces=(
    "net Addr"
)

for iface in "${lib_ifaces[@]}"
do
    parts=($iface)
    folder="lib/mocks"
    package="${parts[0]}"
    file="${parts[1],,}"
    gen_base="$folder/mock_$package"
    mkdir -p "$gen_base"
    mockgen -destination "$folder/mock_$package/mock_$file.go" $iface
done