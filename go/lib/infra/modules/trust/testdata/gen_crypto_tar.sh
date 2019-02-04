#! /bin/bash

# usage: gen_crypto_tar.sh <scion-pki> <output-file>

set -e

DATA=go/lib/infra/modules/trust/testdata
TMP=`mktemp -d`

$1 keys gen -d $DATA -o $TMP "*-*" > /dev/null
$1 trc gen -d $DATA -o $TMP "*" > /dev/null
$1 certs gen -d $DATA -o $TMP "*-*" > /dev/null

tar -C $TMP -cf $2 .
