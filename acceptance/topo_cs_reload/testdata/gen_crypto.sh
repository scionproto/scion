#!/bin/bash

PKIBIN=${1}
OUTTAR=${2}
TMPL=${3}
CRYPTOLIB=${4}

TMP=`mktemp -d`

base64_pwd_gen() {
    dd if=/dev/urandom bs=1 count="${1:-16}" status=none | base64
}

$PKIBIN testcrypto -t $TMPL -o $TMP > /dev/null

CONFDIR=`mktemp -d`
mkdir -p $CONFDIR/certs $CONFDIR/keys $CONFDIR/crypto

mv $TMP/trcs/*.trc $CONFDIR/certs
mv $TMP/AS*/crypto/* $CONFDIR/crypto

base64_pwd_gen > $CONFDIR/keys/master0.key
base64_pwd_gen > $CONFDIR/keys/master1.key

tar -C $CONFDIR -cf $OUTTAR .

rm -rf $TMP $CONFDIR
