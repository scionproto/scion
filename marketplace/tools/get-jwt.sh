#!/bin/sh
# Compatibility wrapper for the historical positional interface. All marketplace login and JWT
# retrieval lives in get_jwt.py; keep this file only for existing callers and shell users.
#
# Usage: marketplace/tools/get-jwt.sh <user> [password] [url] [sub-account]

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 4 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "usage: $0 <user> [password] [url] [sub-account]" >&2
    exit 1
fi

user=$1
password=${2:-1234}
url=${3:-}
sub_account=${4:-}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

set -- python3 "$script_dir/get_jwt.py" "$user" --password "$password"
if [ -n "$url" ]; then
    set -- "$@" --url "$url"
fi
if [ -n "$sub_account" ]; then
    set -- "$@" --sub-account "$sub_account"
fi
exec "$@"
