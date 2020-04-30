#!/bin/bash

# This file contains comments to allow literal includes from our documentation.
# Do not remove or modify them!

export SCION_ROOT=${SCION_ROOT:-$(pwd)}
export PLAYGROUND=${PLAYGROUND:-$SCION_ROOT/scripts/cryptoplayground}
export SAFEDIR=${SAFEDIR:-$(mktemp -d)}
export PATH="$PATH:$SCION_ROOT/bin"

. $PLAYGROUND/crypto_lib.sh

set -e

STARTDATE="20200624120000Z"
ENDDATE="20210624120000Z"

echo "#####################"
echo "# Preparation Phase #"
echo "#####################"

for loc in {bern,geneva,zürich}
do
    echo "Preparation: $loc"
    if [ "$loc" = "bern" ]; then
        IA="1-ff00:0:110"
    elif [ "$loc" = "geneva" ]; then
        IA="1-ff00:0:120"
    else
        IA="1-ff00:0:130"
    fi

    mkdir -p $SAFEDIR/$loc && cd $SAFEDIR/$loc
    set_dirs
    # Generate configuration files
    navigate_pubdir
    basic_conf && sensitive_conf && regular_conf && root_conf && ca_conf && as_conf
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
    in_docker 'navigate_pubdir && gen_sensitive && check_sensitive && gen_regular && check_regular && gen_root && check_root'
    check_sensitive_type && check_regular_type && check_root_type
done

echo "###########"
echo "# Phase 1 #"
echo "###########"


echo "Phase 1: ceremony administrator collects certificates"
mkdir -p $SAFEDIR/admin && cd $SAFEDIR/admin
for loc in {bern,geneva,zürich}
do
    mkdir -p $loc
    cp $SAFEDIR/$loc/public/*.crt $loc
done

# LITERALINCLUDE display_validity START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    openssl x509 -in $cert -noout -dates
    echo ""
done
# LITERALINCLUDE display_validity END

# LITERALINCLUDE display_signature_algo START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    openssl x509 -in $cert -noout -text | grep "Signature Algorithm" | cat
    echo ""
done
# LITERALINCLUDE display_signature_algo END

# LITERALINCLUDE validate_certificate_type START
for cert in {bern,geneva,zürich}/*.crt; do
    scion-pki v2 certs validate --type $(basename $cert .crt) $cert
done
# LITERALINCLUDE validate_certificate_type END

echo "Phase 1: display certificate digests"
echo "-------------------------------"
# LITERALINCLUDE certificates_digest START
for cert in {bern,geneva,zürich}/*.crt; do
    sha256sum $cert
done
# LITERALINCLUDE certificates_digest END
echo "-------------------------------"

for loc in {bern,geneva,zürich}
do
    for other in {bern,geneva,zürich}
    do
        cp -r $other $SAFEDIR/$loc
    done
    echo "Phase 1: $loc check diff"
    diff $SAFEDIR/$loc/public/sensitive-voting.crt $SAFEDIR/$loc/$loc/sensitive-voting.crt
    diff $SAFEDIR/$loc/public/regular-voting.crt $SAFEDIR/$loc/$loc/regular-voting.crt
done

cd $SAFEDIR/bern
set_dirs
# LITERALINCLUDE diff_own_cert START
diff bern/sensitive-voting.crt $PUBDIR/sensitive-voting.crt
diff bern/regular-voting.crt $PUBDIR/regular-voting.crt
# LITERALINCLUDE diff_own_cert END

echo "###########"
echo "# Phase 2 #"
echo "###########"

echo "Phase 2: create payload config"
cd $SAFEDIR/admin
payload_conf

files=''
for file in {bern,geneva,zürich}/*.crt
do
    files="\"$file\",$files"
done
files=${files////\\/} # Magic to make sed happy

sed -i \
    -e 's/{{.ISD}}/1/g' \
    -e 's/{{.Description}}/"Test ISD"/g' \
    -e 's/{{.VotingQuorum}}/2/g' \
    -e 's/{{.CoreASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.AuthoritativeASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.NotBefore}}/1593000000/g' \
    -e 's/{{.Validity}}/"365d"/g' \
    -e "s/{{.CertFiles}}/[$files]/g" \
    ISD-B1-S1.toml

echo "Phase 2: display payload config"
echo "-------------------------------"
cat ISD-B1-S1.toml
echo "-------------------------------"

# LITERALINCLUDE create_payload START
scion-pki v2 trcs payload -t ISD-B1-S1.toml -o ISD-B1-S1.pld.der
# LITERALINCLUDE create_payload END

echo "Phase 2: display payload digest"
echo "-------------------------------"
# LITERALINCLUDE payload_digest START
sha256sum ISD-B1-S1.pld.der
# LITERALINCLUDE payload_digest END
echo "-------------------------------"

echo "Phase 2: copy payload"
cp ISD-B1-S1.pld.der $SAFEDIR/bern
cp ISD-B1-S1.pld.der $SAFEDIR/geneva
cp ISD-B1-S1.pld.der $SAFEDIR/zürich

echo "###########"
echo "# Phase 3 #"
echo "###########"

for loc in {bern,geneva,zürich}
do
    echo "Phase 3: $loc cast vote"
    cd $SAFEDIR/$loc
    set_dirs

    in_docker "cd /workdir && display_payload && sign_payload && check_signed_payload"
    cp ISD-B1-S1.{regular,sensitive}.trc $SAFEDIR/admin/$loc
done

echo "###########"
echo "# Phase 4 #"
echo "###########"

echo "Phase 4: combine TRC"
cd $SAFEDIR/admin

# LITERALINCLUDE combine_payload START
scion-pki v2 trcs combine -p ISD-B1-S1.pld.der \
    bern/ISD-B1-S1.sensitive.trc \
    bern/ISD-B1-S1.regular.trc \
    geneva/ISD-B1-S1.sensitive.trc \
    geneva/ISD-B1-S1.regular.trc \
    zürich/ISD-B1-S1.sensitive.trc \
    zürich/ISD-B1-S1.regular.trc \
    -o ISD-B1-S1.trc
# LITERALINCLUDE combine_payload END

# LITERALINCLUDE verify_payload START
scion-pki v2 trcs verify --anchor ISD-B1-S1.trc ISD-B1-S1.trc
# LITERALINCLUDE verify_payload END
in_docker "cd /workdir && verify_trc"


echo "Phase 4: display trc digest"
echo "---------------------------"
# LITERALINCLUDE trc_digest START
sha256sum ISD-B1-S1.trc
# LITERALINCLUDE trc_digest END
echo "---------------------------"

for loc in {bern,geneva,zürich}
do
    echo "Phase 4: $loc verify"
    cd $SAFEDIR/$loc

    cp $SAFEDIR/admin/ISD-B1-S1.trc .
    set_dirs
    in_docker "cd /workdir && verify_trc && display_signatures"
done

echo "Phase 5: sanity check - generate CA and AS Certificates"
echo "-------------------------------------------------------"

for loc in {bern,geneva,zürich}
do
    echo "Phase 5: $loc"
    cd $SAFEDIR/$loc

    set_dirs
    navigate_pubdir

    echo "Phase 5: $loc generate CA certificate"
    in_docker "navigate_pubdir && gen_ca && check_ca"
    check_ca_type

    echo "Phase 5: $loc generate AS certificate"
    in_docker "navigate_pubdir && gen_as && check_as"
    check_as_type
done

echo "###########"
echo "# Success #"
echo "###########"
echo "Working directory: $SAFEDIR"
