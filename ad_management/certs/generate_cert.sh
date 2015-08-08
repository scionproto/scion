#!/usr/bin/env bash
set -e

CA_CERT=ca.pem
CA_CERT_KEY=ca.key

AD_CERT=ad.pem
AD_CSR=ad.csr
AD_KEY=ad.key

WEBAPP_CERT=webapp.pem
WEBAPP_CSR=webapp.csr
WEBAPP_KEY=webapp.key

# Change directory to the script directory
SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR/"

echo 'Generating CA certificate...'
openssl req -nodes -new -x509 -keyout $CA_CERT_KEY -out $CA_CERT -days 1000 -subj '/CN=webapp_CA'

echo 'Generating AD CSR...'
openssl req -nodes -new -keyout $AD_KEY -out $AD_CSR -subj '/CN=AD_md'
openssl x509 -req -in $AD_CSR -out $AD_CERT -set_serial 01 -days 1000 -CA $CA_CERT -CAkey $CA_CERT_KEY
rm $AD_CSR

echo 'Generating Webapp CSR...'
openssl req -nodes -new -keyout $WEBAPP_KEY -out $WEBAPP_CSR -subj '/CN=Webapp'
openssl x509 -req -in $WEBAPP_CSR -out $WEBAPP_CERT -set_serial 2 -days 1000 -CA $CA_CERT -CAkey $CA_CERT_KEY
rm $WEBAPP_CSR
