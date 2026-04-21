#!/bin/bash

# This file contains comments to allow literal includes from our documentation.
# Do not remove or modify them!

export SCION_ROOT=${SCION_ROOT:-$(pwd)}
export PLAYGROUND=$(realpath "${PLAYGROUND:-$SCION_ROOT/tools/cryptoplayground}")
export SAFEDIR=${SAFEDIR:-$(mktemp -d)}
export SCION_PKI_BIN=${SCION_PKI_BIN:-$SCION_ROOT/bin/scion-pki}
export PATH="$(realpath $(dirname "$SCION_PKI_BIN")):$PATH"
export USE_SCION_PKI_SIGN=${USE_SCION_PKI_SIGN:-}

. $PLAYGROUND/crypto_lib.sh

set -e

if [ ! -d "$SAFEDIR/admin" ]; then
    echo "##################################"
    echo "# Running Base+Sensitive Ceremony #"
    echo "##################################"
    echo ""

    $PLAYGROUND/trc_ceremony_sensitive.sh

    echo "###################################"
    echo "# Finished Base+Sensitive Ceremony #"
    echo "###################################"
    echo ""
fi

if [ -z "$USE_SCION_PKI_SIGN" ]; then
    STARTDATE="20220524120000Z"
    ENDDATE="20230524120000Z"
else
    STARTDATE="2022-05-24T14:00:00+02:00"
    ENDDATE="2023-05-24T14:00:00+02:00"
fi
PREDID="ISD1-B1-S2"
TRCID="ISD1-B1-S3"

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

    # In a regular update, the sensitive voting certificate is unchanged.
    # We version the existing sensitive certificate as the PREDID version,
    # then generate new regular and root certificates only.
    TRCVERSION=$PREDID && version_sensitive && version_regular && version_root

    if [ -z "$USE_SCION_PKI_SIGN" ]; then
        # Generate new regular and root certificates; sensitive stays unchanged
        in_docker 'navigate_pubdir && gen_regular && check_regular && gen_root && check_root'
    else
        # Clean up keys and certificates from sensitive ceremony
        rm -f $KEYDIR/cp-ca.key $KEYDIR/cp-as.key cp-ca.crt cp-as.csr chain.pem

        export ORG=$loc
        regular_cn && gen_regular_scion_pki
        root_cn && gen_root_scion_pki
    fi
    check_regular_type && check_root_type

done

echo "###########"
echo "# Phase 1 #"
echo "###########"


echo "Phase 1: ceremony administrator collects certificates"
mkdir -p $SAFEDIR/admin && cd $SAFEDIR/admin
for loc in {bern,geneva,zürich}
do
    mkdir -p $loc
    # In a regular update, only new regular voting and root certs are shared.
    # The sensitive voting certs are unchanged and come from the predecessor TRC.
    cp $SAFEDIR/$loc/public/{regular-voting,cp-root}.crt $loc
    cp $SAFEDIR/$loc/public/$PREDID/sensitive-voting.crt $loc
done

# LITERALINCLUDE display_validity START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    openssl x509 -in $cert -noout -dates
    echo ""
done
# LITERALINCLUDE display_validity END

# LITERALINCLUDE display_validity_scion-pki START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    scion-pki certificate inspect $cert | grep Validity -A 2
done
# LITERALINCLUDE display_validity_scion-pki END

# LITERALINCLUDE display_signature_algo START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    openssl x509 -in $cert -noout -text | grep "Signature Algorithm" | cat
    echo ""
done
# LITERALINCLUDE display_signature_algo END

# LITERALINCLUDE display_signature_algo_scion-pki START
for cert in {bern,geneva,zürich}/*.crt; do
    echo $cert
    scion-pki certificate inspect $cert | grep -m 1 "Signature Algorithm"
done
# LITERALINCLUDE display_signature_algo_scion-pki END

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
    diff $SAFEDIR/$loc/public/regular-voting.crt $SAFEDIR/$loc/$loc/regular-voting.crt
done

cd $SAFEDIR/bern
set_dirs
# LITERALINCLUDE diff_own_cert START
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
    -e 's/{{.SerialNumber}}/3/g' \
    -e 's/{{.GracePeriod}}/"30d"/g' \
    -e 's/{{.VotingQuorum}}/2/g' \
    -e 's/{{.Votes}}/[1, 4, 7]/g' \
    -e 's/{{.CoreASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.AuthoritativeASes}}/["ff00:0:110", "ff00:0:111"]/g' \
    -e 's/{{.NotBefore}}/"2022-05-24T14:00:00+02:00"/g' \
    -e 's/{{.NotAfter}}/"2023-05-24T14:00:00+02:00"/g' \
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

    display_payload_scion_pki
    if [ -z "$USE_SCION_PKI_SIGN" ]; then
        in_docker "cd /workdir && display_payload && sign_regular_payload && check_regular_signed_payload && regular_vote && check_regular_vote"
    else
        sign_regular_payload_scion_pki
        regular_vote_scion_pki
        check_regular_signed_payload_scion_pki
        check_regular_vote_scion_pki
    fi
    cp $TRCID.{regular,regular.vote}.trc $SAFEDIR/admin/$loc
done

echo "###########"
echo "# Phase 4 #"
echo "###########"

echo "Phase 4: combine TRC"
cd $SAFEDIR/admin

# LITERALINCLUDE combine_payload START
scion-pki trcs combine -p $TRCID.pld.der \
    bern/$TRCID.regular.vote.trc \
    bern/$TRCID.regular.trc \
    geneva/$TRCID.regular.vote.trc \
    geneva/$TRCID.regular.trc \
    zürich/$TRCID.regular.vote.trc \
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
scion-pki trc inspect --predecessor $PREDID.trc $TRCID.trc
# LITERALINCLUDE trc_content END

for loc in {bern,geneva,zürich}
do
    echo "Phase 4: $loc verify"
    cd $SAFEDIR/$loc

    cp $SAFEDIR/admin/$TRCID.trc .
    set_dirs
    scion-pki trcs verify --anchor $PREDID.trc $TRCID.trc
    # LITERALINCLUDE trc_content_rep START
    scion-pki trc inspect --predecessor $PREDID.trc $TRCID.trc
    # LITERALINCLUDE trc_content_rep END

    # LITERALINCLUDE format_trc START
    scion-pki trc format --format pem $TRCID.trc
    # LITERALINCLUDE format_trc END
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
    if [ -z "$USE_SCION_PKI_SIGN" ]; then
        in_docker "navigate_pubdir && gen_ca && check_ca"
        check_ca_type
    else
        gen_ca_scion_pki
    fi
    echo "Phase 5: $loc generate AS certificate"
    if [ -z "$USE_SCION_PKI_SIGN" ]; then
        in_docker "navigate_pubdir && gen_as && check_as"
        check_as_type
        cat cp-as.crt cp-ca.crt > chain.pem
    else
        gen_as_scion_pki
    fi
    scion-pki certs verify --trc ../$TRCID.trc --currenttime 1653393600 chain.pem
done

echo "###########"
echo "# Success #"
echo "###########"
echo "Working directory: $SAFEDIR"
