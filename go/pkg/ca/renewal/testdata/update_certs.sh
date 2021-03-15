#! /bin/bash

set -eo pipefail

PUBDIR="$SAFEDIR"
KEYDIR="$SAFEDIR"
PATH="$PATH:$SCION_ROOT/bin"

. "$PLAYGROUND/crypto_lib.sh"

cd $SAFEDIR
stop_docker || true
start_docker

for loc in {bern,geneva}
do
    echo "Preparation: $loc"
    if [ "$loc" = "bern" ]; then
        IA="1-ff00:0:110"
    else
        IA="1-ff00:0:120"
    fi

    mkdir -p $SAFEDIR/$loc && cd $SAFEDIR/$loc
    set_dirs
    # Generate configuration files
    navigate_pubdir
    basic_conf && root_conf && ca_conf && as_conf
    prepare_ca
    sed -i \
        -e 's/{{.Country}}/CH/g' \
        -e "s/{{.State}}/$loc/g" \
        -e "s/{{.Location}}/$loc/g" \
        -e "s/{{.Organization}}/$loc/g" \
        -e "s/{{.OrganizationalUnit}}/$loc InfoSec Squad/g" \
        -e "s/{{.ISDAS}}/$IA/g" \
        basic.cnf
    for cnf in *.cnf
    do
        sed -i \
        -e "s/{{.ShortOrg}}/$loc/g" \
        $cnf
    done
    # Generate certificates
    #
    # The default start and end date are set by TestUpdateCrypto.
    # For AS certificates we want smaller periods, because we want to check that
    # the database correctly fetches when given a specific point in time.
    KEYDIR=/workdir/$loc/keys PUBDIR=/workdir/$loc/public docker_exec "navigate_pubdir && gen_root && gen_ca \
        && STARTDATE=20210302120000Z ENDDATE=20210306120000Z gen_as && mv cp-as.crt cp-as1.crt && mv cp-as.csr cp-as1.csr && mv \$KEYDIR/cp-as.key cp-as1.key \
        && STARTDATE=20210304120000Z ENDDATE=20210308120000Z gen_as && mv cp-as.crt cp-as2.crt && cp cp-as.csr cp-as2.csr && cp \$KEYDIR/cp-as.key cp-as2.key \
        && STARTDATE=20210306120000Z ENDDATE=20210310120000Z gen_as_ca_steps && mv cp-as.crt cp-as3.crt && mv cp-as.csr cp-as3.csr && mv \$KEYDIR/cp-as.key cp-as3.key\
        && chmod 0755 *.key"

    scion-pki certs validate --type cp-root $PUBDIR/cp-root.crt
    scion-pki certs validate --type cp-ca $PUBDIR/cp-ca.crt
    scion-pki certs validate --type cp-as $PUBDIR/cp-as1.crt
    scion-pki certs validate --type cp-as $PUBDIR/cp-as2.crt
    scion-pki certs validate --type cp-as $PUBDIR/cp-as3.crt

    mkdir -p "$TESTDATA/$loc"
    if [ "$loc" = 'bern' ]; then
        cp $PUBDIR/*.crt "$TESTDATA/$loc"
        cp $PUBDIR/cp-as*.csr "$TESTDATA/$loc"
        cp $PUBDIR/*.key "$TESTDATA/$loc"
    else
        cp $PUBDIR/cp-{ca,root}.crt "$TESTDATA/$loc"
        cp $PUBDIR/cp-as1.crt "$TESTDATA/$loc"
        cp $PUBDIR/cp-as1.key "$TESTDATA/$loc"
    fi
done

stop_docker
