#! /bin/bash

# usage: gen_crypto_tar.sh <scion-pki> <output-file>

set -e

TMP=`mktemp -d`

$1 v2 tmpl topo -d $TMP ./topology/Default.topo > /dev/null
$1 v2 keys gen -d $TMP "*-*" > /dev/null
$1 v2 trcs gen -d $TMP "*" > /dev/null

tar -C $TMP -cf $2 .
