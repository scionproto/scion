# This file is symlinked from documentation!

gen_sensitive() {

    cat << EOF > sensitive-voting.ext
subjectKeyIdentifier = hash
extendedKeyUsage = 1.3.6.1.4.1.55324.1.3.1, 1.3.6.1.5.5.7.3.8
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out sensitive-voting.key
openssl req -out sensitive-voting.csr -key=sensitive-voting.key -new -config basic.cnf
openssl x509 -req -sha512 -days 1825 -in sensitive-voting.csr -extfile sensitive-voting.ext -signkey sensitive-voting.key -out sensitive-voting.crt

}

gen_regular() {

cat << EOF > regular-voting.ext
subjectKeyIdentifier = hash
extendedKeyUsage = 1.3.6.1.4.1.55324.1.3.2, 1.3.6.1.5.5.7.3.8
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out regular-voting.key
openssl req -out regular-voting.csr -key=regular-voting.key -new -config basic.cnf
openssl x509 -req -sha512 -days 365 -in regular-voting.csr -extfile regular-voting.ext -signkey regular-voting.key -out regular-voting.crt

}

gen_root() {

cat << EOF > cp-root.ext
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
extendedKeyUsage = 1.3.6.1.4.1.55324.1.3.3, 1.3.6.1.5.5.7.3.8
basicConstraints = critical, CA:TRUE, pathlen:1
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out cp-root.key
openssl req -out cp-root.csr -key=cp-root.key -new -config basic.cnf
openssl x509 -req -sha512 -days 365 -in cp-root.csr -extfile cp-root.ext -signkey cp-root.key -out cp-root.crt

}

gen_ca() {

cat << EOF > cp-ca.ext
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
basicConstraints = critical, CA:TRUE, pathlen:0
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out cp-ca.key
openssl req -out cp-ca.csr -key=cp-ca.key -new -config basic.cnf
openssl x509 -req -sha512 -days 365 -in cp-ca.csr -extfile cp-ca.ext -CA cp-root.crt -CAkey cp-root.key -CAcreateserial -out cp-ca.crt

}

gen_as() {

cat << EOF > cp-as.ext
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
extendedKeyUsage = 1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.8
authorityKeyIdentifier = keyid
EOF

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out cp-as.key
openssl req -out cp-as.csr -key=cp-as.key -new -config basic.cnf
openssl x509 -req -sha512 -days 365 -in cp-as.csr -extfile cp-as.ext -CA cp-ca.crt -CAkey cp-ca.key -CAcreateserial -out cp-as.crt

}


