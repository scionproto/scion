# This file contains comments to allow literal includes from our documentation.
# Do not remove or modify them!


############
# Navigation
############

set_dirs() {
# LITERALINCLUDE set_dirs START
    export PUBDIR="$(pwd)/public"
    mkdir -p $PUBDIR
    export KEYDIR="$(pwd)/keys"
    mkdir -p $KEYDIR
# LITERALINCLUDE set_dirs END
}

export_paths_base() {
# LITERALINCLUDE export_paths_base START
    # Dir that holds the certificates.
    export PUBDIR="path/to/public"
    # Dir that holds the secret keys.
    export KEYDIR="path/to/keys"
    # The TRC ID of the TRC that is created in the ceremony.
    export TRCID="ISD<isd-id>-B1-S1"
# LITERALINCLUDE export_paths_base END
}

export_paths_update() {
# LITERALINCLUDE export_paths_update START
    # Dir that holds the certificates.
    export PUBDIR="path/to/public"
    # Dir that holds the secret keys.
    export KEYDIR="path/to/keys"
    # The TRC ID of the TRC that is created in the ceremony.
    export TRCID="ISD<isd-id>-B1-S<serial-number>"
    # The TRC ID of the predecessor TRC of this ceremony.
    export PREDID="ISD<isd-id>-B1-S<serial-bumber>"
# LITERALINCLUDE export_paths_update END
}

navigate_pubdir() {
# LITERALINCLUDE navigate_pubdir START
    cd $PUBDIR
# LITERALINCLUDE navigate_pubdir END
}

###############
# Docker helper
###############

start_docker() {
    name=${CONTAINER_NAME:-crypto_lib}

    docker run --name $name \
        -v $(pwd):/workdir \
        -v $PLAYGROUND:/scripts \
        -d emberstack/openssl tail -f /dev/null
}

stop_docker() {
    name=${CONTAINER_NAME:-crypto_lib}

    docker rm -f $name
}

docker_exec() {
    name=${CONTAINER_NAME:-crypto_lib}

    docker exec \
        -e KEYDIR=$KEYDIR \
        -e PUBDIR=$PUBDIR \
        -e STARTDATE=$STARTDATE \
        -e ENDDATE=$ENDDATE \
        -e TRCID=$TRCID \
        -e PREDID=$PREDID \
        $name \
        sh -c "set -e && . /scripts/crypto_lib.sh && $@"
}

in_docker() {
    docker run --rm \
        --user $(id -u):$(id -g) \
        -v $(pwd):/workdir \
        -v $KEYDIR:/keydir \
        -e KEYDIR=/keydir  \
        -v $PUBDIR:/pubdir \
        -e PUBDIR=/pubdir  \
        -v $PLAYGROUND:/scripts \
        -e STARTDATE=$STARTDATE \
        -e ENDDATE=$ENDDATE \
        -e TRCID=$TRCID \
        -e PREDID=$PREDID \
        emberstack/openssl \
        sh -c "set -e && . /scripts/crypto_lib.sh && $@"
}

######################
# Config file creation
######################

PAYLOAD_CONF_SAMPLE=$(cat <<-END
# LITERALINCLUDE payload_conf_sample START
{{.ISD}}               = 1
{{.Description}}       = "Test ISD"
{{.VotingQuorum}}      = 2
{{.CoreASes}}          = ["ff00:0:110", "ff00:0:111"]
{{.AuthoritativeASes}} = ["ff00:0:110", "ff00:0:111"]
{{.NotBefore}}         = 1593000000  # Seconds since UNIX Epoch
{{.Validity}}          = "365d"
{{.CertFiles}} = [
    "bern/sensitive-voting.crt",
    "bern/regular-voting.crt",
    "bern/cp-root.crt",
    "geneva/sensitive-voting.crt",
    "geneva/regular-voting.crt",
    "zürich/sensitive-voting.crt",
    "zürich/regular-voting.crt",
]
# LITERALINCLUDE payload_conf_sample END
END
)

payload_conf() {
# LITERALINCLUDE payload_conf START
cat << EOF > $TRCID.toml
isd                = {{.ISD}}
description        = {{.Description}}
serial_version     = 1
base_version       = 1
voting_quorum      = {{.VotingQuorum}}
core_ases          = {{.CoreASes}}
authoritative_ases = {{.AuthoritativeASes}}
cert_files         = {{.CertFiles}}
no_trust_reset     = false

[validity]
not_before = {{.NotBefore}}
validity   = {{.Validity}}
EOF
# LITERALINCLUDE payload_conf END
}

SENSITIVE_PAYLOAD_CONF_SAMPLE=$(cat <<-END
# LITERALINCLUDE sensitive_payload_conf_sample START
{{.ISD}}               = 1
{{.Description}}       = "Test ISD"
{{.SerialNumber}}      = 2
{{.GracePeriod}}       = "30d"
{{.VotingQuorum}}      = 2
{{.Votes}}             = [0, 3, 5]
{{.CoreASes}}          = ["ff00:0:110", "ff00:0:111"]
{{.AuthoritativeASes}} = ["ff00:0:110", "ff00:0:111"]
{{.NotBefore}}         = 1621857600  # Seconds since UNIX Epoch
{{.Validity}}          = "365d"
{{.CertFiles}} = [
    "bern/sensitive-voting.crt",
    "bern/regular-voting.crt",
    "bern/cp-root.crt",
    "geneva/sensitive-voting.crt",
    "geneva/regular-voting.crt",
    "zürich/sensitive-voting.crt",
    "zürich/regular-voting.crt",
]
# LITERALINCLUDE sensitive_payload_conf_sample END
END
)

sensitive_payload_conf() {
# LITERALINCLUDE sensitive_payload_conf START
cat << EOF > $TRCID.toml
isd                = {{.ISD}}
description        = {{.Description}}
serial_version     = {{.SerialNumber}}
base_version       = 1
grace_period       = {{.GracePeriod}}
voting_quorum      = {{.VotingQuorum}}
votes              = {{.Votes}}
core_ases          = {{.CoreASes}}
authoritative_ases = {{.AuthoritativeASes}}
cert_files         = {{.CertFiles}}
no_trust_reset     = false

[validity]
not_before = {{.NotBefore}}
validity   = {{.Validity}}
EOF
# LITERALINCLUDE sensitive_payload_conf END
}

basic_conf() {
# LITERALINCLUDE basic_conf START
cat << EOF > basic.cnf
[openssl_init]
oid_section = oids

[req]
distinguished_name = req_distinguished_name
prompt             = no

[oids]
ISD-AS        = SCION ISD-AS number, 1.3.6.1.4.1.55324.1.2.1
sensitive-key = SCION sensitive voting key, 1.3.6.1.4.1.55324.1.3.1
regular-key   = SCION regular voting key, 1.3.6.1.4.1.55324.1.3.2
root-key      = SCION CP root key, 1.3.6.1.4.1.55324.1.3.3

[req_distinguished_name]
C      = {{.Country}}
ST     = {{.State}}
L      = {{.Location}}
O      = {{.Organization}}
OU     = {{.OrganizationalUnit}}
CN     = \${common_name::name}
ISD-AS = {{.ISDAS}}

[ca]
default_ca = basic_ca

[basic_ca]
default_days   = \${ca_defaults::default_days}
default_md     = sha512
database       = database/index.txt
new_certs_dir  = certificates
unique_subject = no
rand_serial    = yes
policy         = policy_any

[policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

EOF
# LITERALINCLUDE basic_conf END
}

prepare_ca() {
# LITERALINCLUDE prepare_ca START
    mkdir -p database
    touch database/index.txt
    mkdir -p certificates
# LITERALINCLUDE prepare_ca END
}

sensitive_conf() {
# LITERALINCLUDE sensitive_conf START
cat << EOF > sensitive-voting.cnf
openssl_conf    = openssl_init
x509_extensions = x509_ext

[common_name]
name = {{.ShortOrg}} High Security Voting Certificate

[x509_ext]
subjectKeyIdentifier = hash
extendedKeyUsage     = 1.3.6.1.4.1.55324.1.3.1, 1.3.6.1.5.5.7.3.8

[ca_defaults]
default_days = 1825

.include basic.cnf
EOF
# LITERALINCLUDE sensitive_conf END
}

regular_conf() {
# LITERALINCLUDE regular_conf START
cat << EOF > regular-voting.cnf
openssl_conf    = openssl_init
x509_extensions = x509_ext

[common_name]
name = {{.ShortOrg}} Regular Voting Certificate

[x509_ext]
subjectKeyIdentifier = hash
extendedKeyUsage     = 1.3.6.1.4.1.55324.1.3.2, 1.3.6.1.5.5.7.3.8

[ca_defaults]
default_days = 365

.include basic.cnf
EOF
# LITERALINCLUDE regular_conf END
}

root_conf() {
# LITERALINCLUDE root_conf START
cat << EOF > cp-root.cnf
openssl_conf    = openssl_init
x509_extensions = x509_ext

[common_name]
name = {{.ShortOrg}} High Security Root Certificate

[x509_ext]
basicConstraints     = critical, CA:TRUE, pathlen:1
keyUsage             = critical, keyCertSign
subjectKeyIdentifier = hash
extendedKeyUsage     = 1.3.6.1.4.1.55324.1.3.3, 1.3.6.1.5.5.7.3.8

[ca_defaults]
default_days = 365

.include basic.cnf
EOF
# LITERALINCLUDE root_conf END
}

ca_conf() {
# LITERALINCLUDE ca_conf START
cat << EOF > cp-ca.cnf
openssl_conf    = openssl_init
x509_extensions = x509_ext
req_extensions  = req_ext

[common_name]
name = {{.ShortOrg}} Secure CA Certificate

[x509_ext]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid

[req_ext]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign
subjectKeyIdentifier   = hash

[ca_defaults]
default_days = 11

.include basic.cnf
EOF
# LITERALINCLUDE ca_conf END
}

as_conf() {
# LITERALINCLUDE as_conf START
cat << EOF > cp-as.cnf
openssl_conf    = openssl_init
x509_extensions = x509_ext
req_extensions  = req_ext

[common_name]
name = {{.ShortOrg}} AS Certificate

[x509_ext]
keyUsage               = critical, digitalSignature
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
extendedKeyUsage       = 1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.8

[req_ext]
keyUsage               = critical, digitalSignature
subjectKeyIdentifier   = hash
extendedKeyUsage       = 1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.8

[ca_defaults]
default_days = 3

.include basic.cnf
EOF
# LITERALINCLUDE as_conf END
}

########################
# Certificate generation
########################

gen_sensitive() {
# LITERALINCLUDE gen_sensitive START
    # Uncomment and set the appropriate values:
    #
    # STARTDATE="20200624120000Z"
    # ENDDATE="20250624120000Z"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out $KEYDIR/sensitive-voting.key

    openssl req -new -key $KEYDIR/sensitive-voting.key -config sensitive-voting.cnf \
        -utf8 -out sensitive-voting.csr

    openssl ca -in sensitive-voting.csr -config sensitive-voting.cnf \
        -keyfile $KEYDIR/sensitive-voting.key -selfsign \
        -startdate $STARTDATE -enddate $ENDDATE -preserveDN \
        -notext -batch -utf8 -out sensitive-voting.crt
# LITERALINCLUDE gen_sensitive END
}

check_sensitive() {
# LITERALINCLUDE check_sensitive START
    openssl x509 -in sensitive-voting.crt -noout -dates
    openssl x509 -in sensitive-voting.crt -noout -text | grep -o "Signature Algorithm.*"
# LITERALINCLUDE check_sensitive END
}

check_sensitive_type() {
# LITERALINCLUDE check_sensitive_type START
    scion-pki certs validate --type sensitive-voting sensitive-voting.crt
# LITERALINCLUDE check_sensitive_type END
}

version_sensitive() {
# LITERALINCLUDE version_sensitive START
    # Uncomment and set appropriate value:
    #
    # PREDID="ISD1-B1-S1"

    mkdir -p $KEYDIR/$PREDID $PREDID
    mv $KEYDIR/sensitive-voting.key $KEYDIR/$PREDID/sensitive-voting.key
    mv sensitive-voting.crt $PREDID/sensitive-voting.crt
# LITERALINCLUDE version_sensitive END
}

gen_regular() {
# LITERALINCLUDE gen_regular START
    # Uncomment and set the appropriate values:
    #
    # STARTDATE="20200624120000Z"
    # ENDDATE="20210624120000Z"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out $KEYDIR/regular-voting.key

    openssl req -new -key $KEYDIR/regular-voting.key -config regular-voting.cnf \
        -utf8 -out regular-voting.csr

    openssl ca -in regular-voting.csr -config regular-voting.cnf \
        -keyfile $KEYDIR/regular-voting.key -selfsign \
        -startdate $STARTDATE -enddate $ENDDATE -preserveDN \
        -notext -batch -utf8 -out regular-voting.crt
# LITERALINCLUDE gen_regular END
}

check_regular() {
# LITERALINCLUDE check_regular START
    openssl x509 -in regular-voting.crt -noout -dates
    openssl x509 -in regular-voting.crt -noout -text | grep -o "Signature Algorithm.*"
# LITERALINCLUDE check_regular END
}

check_regular_type() {
# LITERALINCLUDE check_regular_type START
    scion-pki certs validate --type regular-voting regular-voting.crt
# LITERALINCLUDE check_regular_type END
}

version_regular() {
# LITERALINCLUDE version_regular START
    # Uncomment and set appropriate value:
    #
    # PREDID="ISD1-B1-S1"

    mkdir -p $KEYDIR/$PREDID $PREDID
    mv $KEYDIR/regular-voting.key $KEYDIR/$PREDID/regular-voting.key
    mv regular-voting.crt $PREDID/regular-voting.crt
# LITERALINCLUDE version_regular END
}

gen_root() {
# LITERALINCLUDE gen_root START
    # Uncomment and set the appropriate values:
    #
    # STARTDATE="20200624120000Z"
    # ENDDATE="20210624120000Z"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out $KEYDIR/cp-root.key

    openssl req -new -key $KEYDIR/cp-root.key -config cp-root.cnf \
        -utf8 -out cp-root.csr

    openssl ca -in cp-root.csr -config cp-root.cnf \
        -keyfile $KEYDIR/cp-root.key -selfsign \
        -startdate $STARTDATE -enddate $ENDDATE -preserveDN \
        -notext -batch -utf8 -out cp-root.crt
# LITERALINCLUDE gen_root END
}

check_root() {
# LITERALINCLUDE check_root START
    openssl x509 -in cp-root.crt -noout -dates
    openssl x509 -in cp-root.crt -noout -text | grep -o "Signature Algorithm.*"
# LITERALINCLUDE check_root END
}

check_root_type() {
# LITERALINCLUDE check_root_type START
    scion-pki certs validate --type cp-root cp-root.crt
# LITERALINCLUDE check_root_type END
}

version_root() {
# LITERALINCLUDE version_root START
    # Uncomment and set appropriate value:
    #
    # PREDID="ISD1-B1-S1"

    mkdir -p $KEYDIR/$PREDID $PREDID
    mv $KEYDIR/cp-root.key $KEYDIR/$PREDID/cp-root.key
    mv cp-root.crt $PREDID/cp-root.crt
# LITERALINCLUDE version_root END
}

gen_ca() {
# LITERALINCLUDE gen_ca START
    # Uncomment and set the appropriate values:
    #
    # STARTDATE="20200624120000Z"
    # ENDDATE="20200701120000Z"

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out $KEYDIR/cp-ca.key

    openssl req -new -key $KEYDIR/cp-ca.key -config cp-ca.cnf \
        -utf8 -out cp-ca.csr

    openssl ca -in cp-ca.csr -config cp-ca.cnf \
        -keyfile $KEYDIR/cp-root.key -cert cp-root.crt \
        -startdate $STARTDATE -enddate $ENDDATE -preserveDN \
        -notext -batch -utf8 -out cp-ca.crt
# LITERALINCLUDE gen_ca END
}

check_ca() {
# LITERALINCLUDE check_ca START
    openssl x509 -in cp-ca.crt -noout -dates
    openssl x509 -in cp-ca.crt -noout -text | grep -o "Signature Algorithm.*"
# LITERALINCLUDE check_ca END
}

check_ca_type() {
# LITERALINCLUDE check_ca_type START
    scion-pki certs validate --type cp-ca cp-ca.crt
# LITERALINCLUDE check_ca_type END
}

gen_as() {
    gen_as_as_steps
    gen_as_ca_steps
}

gen_as_as_steps() {
# LITERALINCLUDE gen_as_as_steps START
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve -out $KEYDIR/cp-as.key

    openssl req -new -key $KEYDIR/cp-as.key -config cp-as.cnf \
        -utf8 -out cp-as.csr
# LITERALINCLUDE gen_as_as_steps END
}

gen_as_ca_steps() {
# LITERALINCLUDE gen_as_ca_steps START
    # Uncomment and set the appropriate values:
    #
    # STARTDATE="20200624120000Z"
    # ENDDATE="20200627120000Z"

    openssl ca -in cp-as.csr -config cp-as.cnf \
        -keyfile $KEYDIR/cp-ca.key -cert cp-ca.crt \
        -startdate $STARTDATE -enddate $ENDDATE -preserveDN \
        -notext -batch -utf8 -out cp-as.crt
# LITERALINCLUDE gen_as_ca_steps END
}

check_as() {
# LITERALINCLUDE check_as START
    openssl x509 -in cp-as.crt -noout -dates
    openssl x509 -in cp-as.crt -noout -text | grep -o "Signature Algorithm.*"
# LITERALINCLUDE check_as END
}

check_as_type() {
# LITERALINCLUDE check_as_type START
    scion-pki certs validate --type cp-as cp-as.crt
# LITERALINCLUDE check_as_type END
}

#############
# TRC Signing
#############

sign_payload() {
# LITERALINCLUDE sign_payload START
    openssl cms -sign -in $TRCID.pld.der -inform der -md sha512 \
        -signer $PUBDIR/regular-voting.crt \
        -inkey $KEYDIR/regular-voting.key \
        -nodetach -nocerts -nosmimecap -binary -outform der \
        > $TRCID.regular.trc

    openssl cms -sign -in $TRCID.pld.der -inform der -md sha512 \
        -signer $PUBDIR/sensitive-voting.crt \
        -inkey $KEYDIR/sensitive-voting.key \
        -nodetach -nocerts -nosmimecap -binary -outform der \
        > $TRCID.sensitive.trc

    # The cms command allows signing payloads according to the Cryptographic Message
    # Syntax defined in RFC5652.  The main purpose of the cms command is interacting
    # with S/MIME messages, but we can use it to create any CMS signed message with
    # the appropriate flags.
    #
    # -sign:       create a signature on the payload.
    # -in:         payload to be signed.
    # -inform:     the payload format. We have an ASN.1 DER encoded payload.
    # -md:         the digest algorithm. We use SHA-512 in accordance with the
    #              specification.
    # -signer:     signing certificate.
    # -inkey:      private key used to sign authenticated by the certificate in -signer.
    # -nodetach:   include the payload in the resulting signed CMS structure.
    # -nocerts:    do not include the signing certificate.
    # -nosmimecap: do not include smime capabilites.
    # -outform:    the output format of the resulting signed CMS structure.
    #              We use ASN.1 DER.
# LITERALINCLUDE sign_payload END
}

sensitive_vote() {
# LITERALINCLUDE sensitive_vote START
    openssl cms -sign -in $TRCID.pld.der -inform der -md sha512 \
        -signer $PUBDIR/$PREDID/sensitive-voting.crt \
        -inkey $KEYDIR/$PREDID/sensitive-voting.key \
        -nodetach -nocerts -nosmimecap -binary -outform der \
        > $TRCID.sensitive.vote.trc
# LITERALINCLUDE sensitive_vote END
}

regular_vote() {
# LITERALINCLUDE regular_vote START
    openssl cms -sign -in $TRCID.pld.der -inform der -md sha512 \
        -signer $PUBDIR/$PREDID/regular-voting.crt \
        -inkey $KEYDIR/$PREDID/regular-voting.key \
        -nodetach -nocerts -nosmimecap -binary -outform der \
        > $TRCID.regular.vote.trc
# LITERALINCLUDE regular_vote END
}

check_signed_payload() {
# LITERALINCLUDE check_signed_payload START
    openssl cms -verify -in $TRCID.sensitive.trc -inform der \
        -certfile $PUBDIR/sensitive-voting.crt \
        -CAfile $PUBDIR/sensitive-voting.crt \
        -purpose any -no_check_time \
        > /dev/null

    openssl cms -verify -in $TRCID.regular.trc -inform der \
        -certfile $PUBDIR/regular-voting.crt \
        -CAfile $PUBDIR/regular-voting.crt \
        -purpose any -no_check_time \
        > /dev/null

    # The cms command allows verifying payloads according to the Cryptographic
    # Message Syntax defined in RFC5652.  The main purpose of the cms command is
    # interacting with S/MIME messages, but we can use it to verify any CMS
    # signed message with the appropriate flags.
    #
    # -verify:        verify the CMS signed message and extract the payload.
    # -in:            the signed CMS structure.
    # -inform:        the format of the signed CMS structure.
    #                 We have an ASN.1 DER encoded structure.
    # -certfile:      specify the certificates that can be used to verify the payload.
    # -CAFile:        specify the certificates that can verify the certificates in
    #                 -certfile. This is needed because the certificates are self-signed.
    # -purpose any:   ignore the certificate purpose required by S/MIME.
    # -no_check_time: do not check if certificates are valid at the current time.
    #                 This is necessary if any of the certificates have notbefore
    #                 time in the future.
# LITERALINCLUDE check_signed_payload END
}

check_sensitive_vote() {
# LITERALINCLUDE check_sensitive_vote START
    openssl cms -verify -in $TRCID.sensitive.vote.trc -inform der \
        -certfile $PUBDIR/$PREDID/sensitive-voting.crt \
        -CAfile $PUBDIR/$PREDID/sensitive-voting.crt \
        -purpose any -no_check_time \
        > /dev/null
# LITERALINCLUDE check_sensitive_vote END
}

check_regular_vote() {
# LITERALINCLUDE check_regular_vote START
    openssl cms -verify -in $TRCID.regular.vote.trc -inform der \
        -certfile $PUBDIR/$PREDID/regular-voting.crt \
        -CAfile $PUBDIR/$PREDID/regular-voting.crt \
        -purpose any -no_check_time \
        > /dev/null
# LITERALINCLUDE check_regular_vote END
}

verify_trc() {
# LITERALINCLUDE verify_trc START
    cat */*voting.crt >> bundle.crt

    openssl cms -verify -in $TRCID.trc -inform der \
        -certfile bundle.crt -CAfile bundle.crt \
        -purpose any -no_check_time -partial_chain \
        > /tmp/$TRCID.pld.extracted

    # The cms command allows verifying payloads according to the Cryptographic
    # Message Syntax defined in RFC5652.  The main purpose of the cms command is
    # interacting with S/MIME messages, but we can use it to verify any CMS
    # signed message with the appropriate flags.
    #
    # -verify:        verify the CMS signed message and extract the payload.
    # -in:            the signed CMS structure.
    # -inform:        the format of the signed CMS structure.
    #                 We have an ASN.1 DER encoded structure.
    # -certfile:      specify the certificates that can be used to verify the payload.
    # -CAFile:        specify the certificates that can verify the certificates in
    #                 -certfile. This is needed because the certificates are self-signed.
    # -purpose any:   ignore the certificate purpose required by S/MIME.
    # -no_check_time: do not check if certificates are valid at the current time.
    #                 This is necessary if any of the certificates have notbefore
    #                 time in the future.
    #
    # In case any of the voting certificates have the same common name. The
    # verification can fail with the following error: 'Verify error:self signed
    # certificate' This is due to how openssl builds the verification path. To
    # suppress that error, set the -partial_chain flag.

    openssl asn1parse -i -in /tmp/$TRCID.pld.extracted -inform der

    # The asn1parse command is a diagnostic utility that can parse ASN.1 structures.
    #
    # -i:      indent the output according to the depth in the structure.
    # -in:     the input file.
    # -inform: the input format. We have an ASN.1 DER encoded structure.
# LITERALINCLUDE verify_trc END
}

display_payload() {
# LITERALINCLUDE display_payload START
    openssl asn1parse -i -in $TRCID.pld.der -inform der

    # The asn1parse command is a diagnostic utility that can parse ASN.1 structures.
    #
    # -i:      indent the output according to the depth in the structure.
    # -in:     the input file.
    # -inform: the input format. We have an ASN.1 DER encoded structure.
# LITERALINCLUDE display_payload END
}

display_signatures() {
# LITERALINCLUDE display_signatures START
    openssl pkcs7 -in $TRCID.trc -inform der -print -noout

    # The pkcs7 command is a diagnostic utility that can inspect PKCS#7
    # structures.  Our CMS signed payload is compatible with PKCS#7.
    #
    # -in:     the input file.
    # -inform: the input format. We have an ASN.1 DER encoded structure.
    # -print:  display the full parsed structure.
    # -noout:  do not display the encoded structure.
# LITERALINCLUDE display_signatures END
}
