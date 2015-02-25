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
    Unit tests for certificate.py and asymcrypto.py.
    """

    def test(self):
        """
        Create a certificate chain and verify it with a TRC file. Sign a message
        with the private key of the last certificate in the chain and verify it.
        """
        cert10 = \
            Certificate('../topology/ISD1/certificates/ISD:1-AD:10-V:0.crt')
        cert19 = \
            Certificate('../topology/ISD1/certificates/ISD:1-AD:19-V:0.crt')
        cert16 = \
            Certificate('../topology/ISD1/certificates/ISD:1-AD:16-V:0.crt')
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
