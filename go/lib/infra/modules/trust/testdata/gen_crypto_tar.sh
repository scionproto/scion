#! /bin/bash

# usage: gen_crypto_tar.sh <scion-pki> <output-file>
#
# This script is run by bazel to generate the testsdata for the trust store
# tests. Crypto material needs to generate dynamically and cannot be commited
# to the tree because it expires. To use the regular go toolchain, create the
# crypto.tar by running the follwing command from the porject root:
#
# ```./go/lib/infra/modules/trust/testdata/gen_crypto_tar.sh```
#
# Example: (generate crypto tar from root dir)
# CRYPTO_PATH="./go/lib/infra/modules/trust/testdata"
# $CRYPTO_PATH/gen_crypto_tar.sh ./bin/scion-pki $CRYPTO_PATH/crypto.tar
set -e

PKIBIN=${1:-./bin/scion-pki}
OUTDIR=${2:-./go/lib/infra/modules/trust/testdata/crypto.tar}

TMP=`mktemp -d`

# Generate config files for the default topology.
$PKIBIN tmpl topo -d $TMP ./topology/Default.topo > /dev/null
# Generate the private keys for all ASes under $TMP/ISD*/AS*/keys.
$PKIBIN keys private -d $TMP "*-*" > /dev/null

# Generate the base TRCs for all ISDs under $TMP/ISD*/trcs/ISD*-V1.trc.
$PKIBIN trcs gen -d $TMP "*" > /dev/null
# Generate three additional updates for ISD 1 under $TMP/ISD1/trcs/ISD1-V{2..4}.trc.
for i in {2..4}
do
    sed -e "s/^version = 1/version = $i/g" \
        -e 's/^votes = \[\]/votes = \["ff00:0:110", "ff00:0:120"\]/g' \
        -e 's/^grace_period = "0s"/grace_period = "1h"/g' \
        $TMP/ISD1/trc-v1.toml > $TMP/ISD1/trc-v$i.toml
    $PKIBIN trcs gen -d $TMP --version $i "1" > /dev/null
done

# Generate the issuer certificates for all issuing ASes under $TMP/ISD*/AS*/certs/*.issuer.
$PKIBIN certs issuer -d $TMP "*-*" > /dev/null
# Generate the certificate chains for all ASes under $TMP/ISD*/AS*/certs/*.crt.
$PKIBIN certs chain -d $TMP "*-*" > /dev/null

tar -C $TMP -cf $OUTDIR .
