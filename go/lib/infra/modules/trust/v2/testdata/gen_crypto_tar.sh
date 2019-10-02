#! /bin/bash

# usage: gen_crypto_tar.sh <scion-pki> <output-file>
#
# Example: (generate crypto tar from root dir)
# CRYPTO_PATH="./go/lib/infra/modules/trust/v2/testdata"
# $CRYPTO_PATH/gen_crypto_tar.sh ./bin/scion-pki $CRYPTO_PATH/crypto.tar
set -e

TMP=`mktemp -d`

$1 v2 tmpl topo -d $TMP ./topology/Default.topo > /dev/null
$1 v2 keys gen -d $TMP "*-*" > /dev/null
$1 v2 trcs gen -d $TMP "*" > /dev/null

tar -C $TMP -cf $2 .
