#!/bin/bash

PKIBIN=${1}
OUTTAR=${2}
TMPL=${3}

TMP=`mktemp -d`

base64_pwd_gen() {
    dd if=/dev/urandom bs=1 count="${1:-16}" status=none | base64
}

$PKIBIN tmpl topo -d $TMP $TMPL > /dev/null
$PKIBIN keys private -d $TMP "*-*" > /dev/null
$PKIBIN trcs gen -d $TMP "*" > /dev/null
$PKIBIN certs issuer -d $TMP "*-*" > /dev/null
$PKIBIN certs chain -d $TMP "*-*" > /dev/null

mkdir -p $TMP/certs
mkdir -p $TMP/keys
mv $TMP/ISD1/trcs/*.trc $TMP/certs
mv $TMP/ISD1/AS*/certs/* $TMP/certs
mv $TMP/ISD1/AS*/keys/* $TMP/keys
base64_pwd_gen > $TMP/keys/master0.key
base64_pwd_gen > $TMP/keys/master1.key
rm -r $TMP/ISD1
tar -C $TMP -cf $OUTTAR .
