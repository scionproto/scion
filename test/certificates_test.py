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

from lib.crypto.certificate import verify_sig_chain_trc, CertificateChain, TRC
from lib.crypto.asymcrypto import sign
from lib.util import (get_cert_file_path, get_trc_file_path, read_file,
    get_sig_key_file_path)
import unittest
import logging
import base64


class TestCertificates(unittest.TestCase):
    """
    Unit tests for certificate.py and asymcrypto.py.
    """

    def test(self):
        """
        Create a certificate chain and verify it with a TRC file. Sign a message
        with the private key of the last certificate in the chain and verify it.
        """
        cert10 = CertificateChain(get_cert_file_path(1, 10, 1, 10, 0))
        trc = TRC(get_trc_file_path(1, 10, 1, 0))
        print('TRC verification', trc.verify())
        print('Cert Chain verification:', cert10.verify('ISD:1-AD:10', trc, 0))

        sig_priv10 = read_file(get_sig_key_file_path(1, 10, 0))
        sig_priv10 = base64.b64decode(sig_priv10)
        msg = b'abcd'
        sig = sign(msg, sig_priv10)
        print('Sig test:', verify_sig_chain_trc(msg, sig, 'ISD:1-AD:10', cert10,
            trc, 0))

        sig_priv13 = read_file(get_sig_key_file_path(1, 13, 0))
        sig_priv13 = base64.b64decode(sig_priv13)
        msg = b'abd'
        sig = sign(msg, sig_priv13)
        chain = CertificateChain.from_values([])
        print('Sig test 2:', verify_sig_chain_trc(msg, sig, 'ISD:1-AD:13',
            cert10, trc, 0))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
