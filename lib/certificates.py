"""
certificates.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import ed25519, time, json, logging
from ed25519 import SigningKey, VerifyingKey


def generate_keys():
    """
    Generates a pair of keys and returns them in base64 format.
    """
    (signing_key, verifyng_key) = ed25519.create_keypair()
    sk_ascii = signing_key.to_ascii(encoding="base64")
    vk_ascii = verifyng_key.to_ascii(encoding="base64")
    return (sk_ascii, vk_ascii)


def generate_certificate(subject, sub_pub_key, issuer, iss_priv_key, version):
    """
    Generates a certificate storing in it relevant information about subject,
    issuer and validity of the certificate itself.
    """
    issuing_time = int(time.time())
    expiration_time = issuing_time + 365*24*60*60
    cert = {'subject': subject,
            'subject_pub_key': str(sub_pub_key)[2:-1],
            'issuer': issuer,
            'version': version,
            'issuing_time': issuing_time,
            'expiration_time': expiration_time,
            'algorithm': 'ed25519'}
    cert_str = json.dumps(cert, sort_keys=True)
    signing_key = SigningKey(iss_priv_key, encoding="base64")
    signature = signing_key.sign(str.encode(cert_str), encoding="base64")
    cert['signature'] = str(signature)[2:-1]
    cert_str = json.dumps(cert, sort_keys=True)
    return cert_str


def verify_certificate(cert, issuer_cert):
    """
    One step verification.
    """
    try:
        cert = json.loads(cert)
        signature = cert['signature']
        del cert['signature']
        cert_str = json.dumps(cert, sort_keys=True)
    except (ValueError, KeyError, TypeError):
        logging.error("Certificate: JSON format error.")
    try:
        issuer_cert = json.loads(issuer_cert)
        iss_pub_key = issuer_cert['subject_pub_key']
        iss_pub_key = bytes(iss_pub_key, 'ascii')
        verifyng_key = VerifyingKey(iss_pub_key, encoding="base64")
    except (ValueError, KeyError, TypeError):
        logging.error("Issuer certificate: JSON format error.")
    try:
        verifyng_key.verify(signature, str.encode(cert_str), encoding="base64")
        return True
    except ed25519.BadSignatureError:
        return False


def build_certificate_chain(chain, cert):
    """
    At every hop, the current AD adds to the chain of certificates
    a certificate signed by himself.
    """
    try:
        cert = json.loads(cert)
    except (ValueError, KeyError, TypeError):
        logging.error("Certificate: JSON format error.")
    try:
        chain = json.loads(chain)
    except (ValueError, KeyError, TypeError):
        logging.error("Certificate Chain: JSON format error.")
    chain[str(len(chain))] = cert
    chain_str = json.dumps(chain, sort_keys=True)
    return chain_str


def verify_certificate_chain(chain, root_cert):
    """
    Entire chain verification. First split the chain and then, for each pair,
    call verify_certificate.
    """
    try:
        chain = json.loads(chain)
    except (ValueError, KeyError, TypeError):
        logging.error("Certificate Chain: JSON format error.")
    if len(chain) == 0:
        return False
    cert = json.dumps(chain["0"], sort_keys=True)
    for index in range(1, len(chain)):
        issuer_cert = json.dumps(chain[str(index)], sort_keys=True)
        if verify_certificate(cert, issuer_cert) == False:
            return False
        cert = issuer_cert
    if verify_certificate(cert, root_cert) == False:
        return False
    return True


class Certificate(object):
    """
    Certificate class.
    """
    def __init__(self, raw=None):
        self.raw = raw
        self.subject = ''
        self.subject_pub_key = ''
        self.issuer = ''
        self.version = 0
        self.issuing_time = 0
        self.expiration_time = 0
        self.algorithm = ''
        self.signature = ''
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Initializes a certificate object out of a raw certificate.
        """
        try:
            cert = json.loads(raw)
        except (ValueError, KeyError, TypeError):
            logging.error("Certificate: JSON format error.")
        self.subject = cert['subject']
        self.subject_pub_key = cert['subject_pub_key']
        self.issuer = cert['issuer']
        self.version = cert['version']
        self.issuing_time = cert['issuing_time']
        self.expiration_time = cert['expiration_time']
        self.algorithm = cert['algorithm']
        self.signature = cert['signature']

    def __str__(self):
        cert_str = json.loads(self.raw)
        cert_str = json.dumps(cert_str, sort_keys=True)
        cert_str = cert_str.replace('{', '{\n\t')
        cert_str = cert_str.replace(', ', ',\n\t')
        cert_str = cert_str.replace('}', '\n}')
        return cert_str


class CertificateChain(object):
    """
    CertificateChain class.
    """
    def __init__(self, raw=None):
        self.raw = raw
        self.certs = {}
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Initializes a certificate chain object out of a raw certificate chain.
        """
        try:
            chain = json.loads(raw)
        except (ValueError, KeyError, TypeError):
            logging.error("Certificate Chain: JSON format error.")
        for index in range(0, len(chain)):
            cert = json.dumps(chain[str(index)], sort_keys=True)
            self.certs[index] = Certificate(cert)

    def __str__(self):
        certs = []
        for index in range(0, len(self.certs)):
            certs.append(str(self.certs[index]))
        chain_str = '\n'.join(certs)
        return chain_str


def main():
    """
    Main function.
    """
    logging.basicConfig(level=logging.DEBUG)
    (priv0, pub0) = generate_keys()
    cert0 = generate_certificate('ISD:11,AD:0', pub0, 'ISD:11,AD:0', priv0, 0)
    (priv1, pub1) = generate_keys()
    cert1 = generate_certificate('ISD:11,AD:1', pub1, 'ISD:11,AD:0', priv0, 0)
    (priv2, pub2) = generate_keys()
    cert2 = generate_certificate('ISD:11,AD:2', pub2, 'ISD:11,AD:1', priv1, 0)
    (priv3, pub3) = generate_keys()
    cert3 = generate_certificate('ISD:11,AD:3', pub3, 'ISD:11,AD:2', priv2, 0)

    chain = '{\n}'
    chain = build_certificate_chain(chain, cert3)
    chain = build_certificate_chain(chain, cert2)
    chain = build_certificate_chain(chain, cert1)
    print("Raw Certificate Chain:\n", chain)

    print("\nCertificate Chain verification:",
          verify_certificate_chain(chain, cert0))

    chain = CertificateChain(chain)
    print("\nCertificateChain class printout\n", chain)


if __name__ == "__main__":
    main()
