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
from lib.crypto.trc import *
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
        cert10 = Certificate('../topology/ISD1/certificates/ISD:1-AD:10-V:0.crt')
        cert19 = Certificate('../topology/ISD1/certificates/ISD:1-AD:19-V:0.crt')
        cert16 = Certificate('../topology/ISD1/certificates/ISD:1-AD:16-V:0.crt')
        trc = TRC('../topology/ISD1/ISD:1-V:0.crt')
        print('TRC verification', trc.verify())
        print('Cert verification:', cert10.verify('ISD:1-AD:10', cert19))

        chain_list = [cert10, cert19, cert16]
        chain = CertificateChain.from_values(chain_list)
        print ('Cert Chain verification:', chain.verify('ISD:1-AD:10', trc, 0))

        with open('../topology/ISD1/signature_keys/ISD:1-AD:10-V:0.key') as fh:
            sig_priv10 = fh.read()
        msg = 'abcd'
        sig = sign(msg, sig_priv10)
        print('Sig test:', verify(msg, sig, 'ISD:1-AD:10', chain, trc, 0))

        with open('../topology/ISD1/signature_keys/ISD:1-AD:13-V:0.key') as fh:
            sig_priv13 = fh.read()
        msg = 'abd'
        sig = sign(msg, sig_priv13)
        chain = CertificateChain.from_values([])
        print('Other Sig test:', verify(msg, sig, 'ISD:1-AD:13', chain, trc, 0))

        """
        print ('CryptoBox Test...')
        print ('ISD:11-AD:3 encrypts message hello to ISD:11-AD:2:')
        cipher = encrypt(msg.encode('utf-8'), priv3, 'ISD:11-AD:2', chain)
        print ('Cipher:', cipher, sep='\n')
        print ('ISD:11-AD:2 decrypts cipher:')
        decipher = decrypt(cipher, priv2, 'ISD:11-AD:3', chain)
        print ('Decrypted message:', str(decipher), sep='\n')
        """

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
