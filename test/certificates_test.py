# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`certificates_test` --- SCION certificates unit test
===========================================
"""

from lib.crypto.certificate import *
from lib.crypto.asymcrypto import *
import unittest


class TestCertificates(unittest.TestCase):
    """
    Unit tests for certificates.py and asymcrypto.py.
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
        (sign0, verify0) = generate_signature_keypair()
        (priv0, pub0) = generate_cryptobox_keypair()
        cert0 = Certificate.from_values('ISD:11-AD:0', verify0, pub0,
                                        'ISD:11-AD:0', sign0, 0)
        (sign1, verify1) = generate_signature_keypair()
        (priv1, pub1) = generate_cryptobox_keypair()
        cert1 = Certificate.from_values('ISD:11-AD:1', verify1, pub1,
                                        'ISD:11-AD:0', sign0, 0)
        (sign2, verify2) = generate_signature_keypair()
        (priv2, pub2) = generate_cryptobox_keypair()
        cert2 = Certificate.from_values('ISD:11-AD:2', verify2, pub2,
                                        'ISD:11-AD:1', sign1, 0)
        (sign3, verify3) = generate_signature_keypair()
        (priv3, pub3) = generate_cryptobox_keypair()
        cert3 = Certificate.from_values('ISD:11-AD:3', verify3, pub3,
                                        'ISD:11-AD:2', sign2, 0)
        print('Certificate:', cert0, sep='\n')

        chain_list = [cert3, cert2, cert1]
        chain = CertificateChain.from_values(chain_list)
        print('Certificate Chain:', chain, sep='\n')

        with open('ISD:11-AD:0-V:0.crt', "w") as file_handler:
                  file_handler.write(str(cert0))

        roots = load_root_certificates('./')
        print ('Certificate Chain verification:',
               chain.verify('ISD:11-AD:3', roots, 0), sep='\n')

        print ('Signature Test...')
        msg = 'hello'
        msg_with_sig = sign(msg.encode('utf-8'), sign3)
        print('Message(With Signature):', msg_with_sig, sep='\n')
        print('Message verification:', verify(msg_with_sig, 'ISD:11-AD:3',
              chain, roots, 0), sep='\n')
        
        print ('CryptoBox Test...')
        print ('ISD:11-AD:3 encrypts message hello to ISD:11-AD:2:')
        cipher = encrypt(msg.encode('utf-8'), priv3, 'ISD:11-AD:2', chain)
        print ('Cipher:', cipher, sep='\n')
        print ('ISD:11-AD:2 decrypts cipher:')
        decipher = decrypt(cipher, priv2, 'ISD:11-AD:3', chain)
        print ('Decrypted message:', str(decipher), sep='\n')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
