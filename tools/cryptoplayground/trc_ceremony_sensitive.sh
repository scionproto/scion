#!/bin/bash

# This file contains comments to allow literal includes from our documentation.
# Do not remove or modify them!

export SCION_ROOT=${SCION_ROOT:-$(pwd)}
export PLAYGROUND=${PLAYGROUND:-$SCION_ROOT/scripts/cryptoplayground}
export SAFEDIR=${SAFEDIR:-$(mktemp -d)}
export PATH="$PATH:$SCION_ROOT/bin"

. $PLAYGROUND/crypto_lib.sh

if [ ! -d "$SAFEDIR/admin" ]; then
    echo "#########################"
    echo "# Running Base Ceremony #"
    echo "#########################"
    echo ""

    $PLAYGROUND/trc_ceremony.sh

    echo "##########################"
    echo "# Finished Base Ceremony #"
    echo "##########################"
    echo ""
fi

set -e

STARTDATE="20210524120000Z"
ENDDATE="20220524120000Z"
PREDID="ISD1-B1-S1"
TRCID="ISD1-B1-S2"

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

    TRCVERSION=$PREDID && version_sensitive && version_regular && version_root

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
    cp $SAFEDIR/$loc/public/{sensitive-voting,regular-voting,cp-root}.crt $loc
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
    scion-pki certs validate --type $(basename $cert .crt) $cert
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
sensitive_payload_conf

files=''
for file in {bern,geneva,zürich}/*.crt
do
    files="\"$file\",$files"
done
files=${files////\\/} # Magic to make sed happy

sed -i \
    -e 's/{{.ISD}}/1/g' \
    -e 's/{{.Description}}/"Test ISD"/g' \
    -e 's/{{.SerialNumber}}/2/g' \
    -e 's/{{.GracePeriod}}/"30d"/g' \
    -e 's/{{.VotingQuorum}}/2/g' \
    -e 's/{{.Votes}}/[0, 3, 6]/g' \
    -e 's/{{.CoreASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.AuthoritativeASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.NotBefore}}/1621857600/g' \
    -e 's/{{.Validity}}/"365d"/g' \
    -e "s/{{.CertFiles}}/[$files]/g" \
    $TRCID.toml

echo "Phase 2: display payload config"
echo "-------------------------------"
cat $TRCID.toml
echo "-------------------------------"

# LITERALINCLUDE create_payload START
scion-pki trcs payload --predecessor $PREDID.trc --template $TRCID.toml --out $TRCID.pld.der
# LITERALINCLUDE create_payload END

echo "Phase 2: display payload digest"
echo "-------------------------------"
# LITERALINCLUDE payload_digest START
sha256sum $TRCID.pld.der
# LITERALINCLUDE payload_digest END
echo "-------------------------------"

echo "Phase 2: copy payload"
cp $TRCID.pld.der $SAFEDIR/bern
cp $TRCID.pld.der $SAFEDIR/geneva
cp $TRCID.pld.der $SAFEDIR/zürich

echo "###########"
echo "# Phase 3 #"
echo "###########"

for loc in {bern,geneva,zürich}
do
    echo "Phase 3: $loc cast vote"
    cd $SAFEDIR/$loc
    set_dirs

    in_docker "cd /workdir && display_payload && sign_payload && check_signed_payload && sensitive_vote && check_sensitive_vote"
    cp $TRCID.{regular,sensitive,sensitive.vote}.trc $SAFEDIR/admin/$loc
done

echo "###########"
echo "# Phase 4 #"
echo "###########"

echo "Phase 4: combine TRC"
cd $SAFEDIR/admin

# LITERALINCLUDE combine_payload START
scion-pki trcs combine -p $TRCID.pld.der \
    bern/$TRCID.sensitive.vote.trc \
    bern/$TRCID.sensitive.trc \
    bern/$TRCID.regular.trc \
    geneva/$TRCID.sensitive.vote.trc \
    geneva/$TRCID.sensitive.trc \
    geneva/$TRCID.regular.trc \
    zürich/$TRCID.sensitive.vote.trc \
    zürich/$TRCID.sensitive.trc \
    zürich/$TRCID.regular.trc \
    -o $TRCID.trc
# LITERALINCLUDE combine_payload END

# LITERALINCLUDE verify_payload START
scion-pki trcs verify --anchor $PREDID.trc $TRCID.trc
# LITERALINCLUDE verify_payload END


echo "Phase 4: display trc digest"
echo "---------------------------"
# LITERALINCLUDE trc_digest START
sha256sum $TRCID.trc
# LITERALINCLUDE trc_digest END
echo "---------------------------"

echo "Phase 4: display trc contents"
# LITERALINCLUDE trc_content START
scion-pki trcs human --predecessor $PREDID.trc $TRCID.trc
# LITERALINCLUDE trc_content END

for loc in {bern,geneva,zürich}
do
    echo "Phase 4: $loc verify"
    cd $SAFEDIR/$loc

    cp $SAFEDIR/admin/$TRCID.trc .
    set_dirs
    scion-pki trcs verify --anchor $PREDID.trc $TRCID.trc
    # LITERALINCLUDE trc_content_rep START
    scion-pki trcs human --predecessor $PREDID.trc $TRCID.trc
    # LITERALINCLUDE trc_content_rep END
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
    cat cp-as.crt cp-ca.crt > chain.pem
    scion-pki certs verify --trc ../$TRCID.trc --currenttime 1621857600 chain.pem
done

echo "###########"
echo "# Success #"
echo "###########"
echo "Working directory: $SAFEDIR"
