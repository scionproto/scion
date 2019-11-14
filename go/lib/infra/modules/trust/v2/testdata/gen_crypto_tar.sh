#! /bin/bash

# usage: gen_crypto_tar.sh <scion-pki> <output-file>
#
# Example: (generate crypto tar from root dir)
# CRYPTO_PATH="./go/lib/infra/modules/trust/v2/testdata"
# $CRYPTO_PATH/gen_crypto_tar.sh ./bin/scion-pki $CRYPTO_PATH/crypto.tar
set -e

TMP=`mktemp -d`

$1 v2 tmpl topo -d $TMP ./topology/Default.topo > /dev/null
$1 v2 keys private -d $TMP "*-*" > /dev/null

$1 v2 trcs gen -d $TMP "*" > /dev/null
for i in {2..4}
do
    sed -e "s/^version = 1/version = $i/g" \
        -e 's/^votes = \[\]/votes = \["ff00:0:110", "ff00:0:120"\]/g' \
        -e 's/^grace_period = "0s"/grace_period = "1h"/g' \
        $TMP/ISD1/trc-v1.toml > $TMP/ISD1/trc-v$i.toml
    $1 v2 trcs gen -d $TMP --version $i "1" > /dev/null
done

$1 v2 certs issuer -d $TMP "*-*" > /dev/null
$1 v2 certs chain -d $TMP "*-*" > /dev/null

tar -C $TMP -cf $2 .
