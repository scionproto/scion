"""
certificates_test.py

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
from lib.crypto.certificates import *
from lib.crypto.asymcrypto import *
import unittest


class TestCertificates(unittest.TestCase):
    """
    Unit tests for certificates.py.
    """

    def test(self):
        """
        Creates 4 private/public key pairs (priv0 and pub0 are used as root
        keys) and 4 certificates, cert0 - cert3. cert0 is self signed (root
        certificate) while the others are signed by the AD above (i.e.,
        AD0--signs-->AD1--signs-->AD2...). Afterwards the certificate chain is
        created and verified. In the end a simple message is signed and the
        resulting signature is then verified.
        """
        (priv0, pub0, enc_pri0, enc_pub0) = generate_keys()
        cert0 = Certificate.from_values('ISD:11-AD:0', pub0, enc_pub0, 'ISD:11-AD:0',
        	priv0, 0)
        (priv1, pub1, enc_pri1, enc_pub1) = generate_keys()
        cert1 = Certificate.from_values('ISD:11-AD:1', pub1, enc_pub1, 'ISD:11-AD:0',
            priv0, 0)
        (priv2, pub2, enc_pri2, enc_pub2) = generate_keys()
        cert2 = Certificate.from_values('ISD:11-AD:2', pub2, enc_pub2, 'ISD:11-AD:1',
            priv1, 0)
        (priv3, pub3, enc_pri3, enc_pub3) = generate_keys()
        cert3 = Certificate.from_values('ISD:11-AD:3', pub3, enc_pub3, 'ISD:11-AD:2',
            priv2, 0)
        print("Certificate:", cert0, sep='\n')

        chain_list = [cert3, cert2, cert1]
        chain = CertificateChain.from_values(chain_list)
        print("Certificate Chain:", chain, sep='\n')

        path = "topology/ISD11/certificates/"
        if not os.path.exists(path):
            os.makedirs(path)
        with open(path + 'ISD:11-AD:0-V:0.crt', "w") as file_handler:
            file_handler.write(str(cert0))

        roots = load_root_certificates(path)
        print("Certificate Chain verification:",
            chain.verify('ISD:11-AD:3', roots, 0), sep='\n')

        print("\nSignature Test...")
        packmsg = sign('hello', priv3)
        print("Message(With Signature):", packmsg, sep='\n')
        print("Message verification:", verify(packmsg, 'ISD:11-AD:3', chain, roots, 0), sep='\n')
        
        print("\nPublic-key Enryption Test...")
        print("ISD:11-AD:3 encrypts message hello to ISD:11-AD:2:")
        cipher = authenticated_encrypt('hello', enc_pri3, 'ISD:11-AD:2', chain)
        print("Cipher:", cipher, sep='\n')
        print("ISD:11-AD:2 decrypts cipher:")
        decipher = authenticated_decrypt(cipher, enc_pri2, 'ISD:11-AD:3', chain)
        print("Decrypted message:", str(decipher), sep='\n')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
