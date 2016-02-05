# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`lib_opt_drkey_test` --- lib.opt.drkey tests
=====================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.opt.drkey import (
    DRKeyRequestKey,
    DRKeyReplyKey,
    DRKeySendKeys,
    DRKeyAcknowledgeKeys,
    parse_drkey_payload,
    DRKeyRequestCertChain,
    DRKeyReplyCertChain)
from test.testcommon import (
    create_mock,
)


class TestDRKeyRequestKey(object):
    """
    Unit tests for lib.opt.drkey.DRKeyRequestKey
    """

    @patch("lib.opt.drkey.CertificateChain")
    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.opt.drkey.DRKeyRequestKey._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = b"hop", b"session_id", \
                               bytes([0x00, 0x00, 0x00, 0x11]), b"CertChain"
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeyRequestKey()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        ntools.eq_(inst.hop, b"hop")
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.cc_length, 17)
        ntools.eq_(inst.certificate_chain, "CertChain")
        data.pop.assert_any_call(17)

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeyRequestKey.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        cert_chain = bytes.fromhex("ffeeddccbbaa99887766554433221100")

        inst = DRKeyRequestKey.from_values(0x3, session_id,
                                           create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = cert_chain

        expected = b"".join([bytes([0x3]), session_id,
                             bytes([0x00, 0x00, 0x00, len(cert_chain)]),
                             cert_chain])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeyRequestKey.__len__
        """
        inst = DRKeyRequestKey.from_values(1, bytes(16), create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = bytes(32)
        # Call
        ntools.eq_(len(inst), 1 + 16 + 4 + 32)


class TestDRKeyReplyKey(object):
    """
    Unit tests for lib.opt.drkey.DRKeyRequestKey
    """
    @patch("lib.opt.drkey.CertificateChain")
    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.opt.drkey.DRKeyReplyKey._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"hop",
                                b"session_id",
                                bytes([0x00, 0x01]),
                                b"encrypted key",
                                bytes([0x00, 0x02]),
                                b"signature",
                                bytes([0x00, 0x03]),
                                b"certificate chain"
                                )
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeyReplyKey()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        data.pop.assert_any_call(1)
        data.pop.assert_any_call(2)
        data.pop.assert_any_call(3)
        ntools.eq_(inst.hop, b"hop")
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.cipher_length, 1)
        ntools.eq_(inst.cipher, b"encrypted key")
        ntools.eq_(inst.sign_length, 2)
        ntools.eq_(inst.signature, b"signature")
        ntools.eq_(inst.cc_length, 3)
        ntools.eq_(inst.certificate_chain, "certificate chain")

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeyReplyKey.pack
        """
        hop = 0x12
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        enc_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeyReplyKey.from_values(hop, session_id, enc_key, signature,
                                         create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain
        expected = b"".join([bytes([hop]),
                             session_id,
                             bytes([0x00, 0x10]),
                             enc_key,
                             bytes([0x00, 0x0d]),
                             signature,
                             bytes([0x00, 0x00, 0x00, 0x1b]),
                             certificate_chain
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeyReplyKey.__len__
        """
        hop = 0x12
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        enc_key = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeyReplyKey.from_values(hop, session_id, enc_key, signature,
                                         create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain

        ntools.eq_(len(inst), 1 + 16 + 2 + len(enc_key) + 2 + len(signature) +
                   4 + len(certificate_chain))


class TestDRKeySendKeys(object):
    """
    Unit tests for lib.opt.drkey.DRKeySendKeys
    """
    @patch("lib.opt.drkey.CertificateChain")
    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.opt.drkey.DRKeySendKeys._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"session_id",
                                bytes([0x00, 0x0a]),
                                b"cipher",
                                bytes([0x00, 0x0b]),
                                b"signature",
                                bytes([0x00, 0x00, 0x00, 0x0c]),
                                b"certificate_chain"
                                )
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeySendKeys()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        data.pop.assert_any_call(0x0a)
        data.pop.assert_any_call(0x0b)
        data.pop.assert_any_call(0x0c)
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.cipher_length, 0x0a)
        ntools.eq_(inst.cipher, b"cipher")
        ntools.eq_(inst.sign_length, 0x0b)
        ntools.eq_(inst.signature, b"signature")
        ntools.eq_(inst.cc_length, 0x0c)
        ntools.eq_(inst.certificate_chain, "certificate_chain")

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeySendKeys.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = b"can i haz cheezburger"
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeySendKeys.from_values(session_id, cipher, signature,
                                         create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain
        expected = b"".join([session_id,
                             bytes([0x00, 0x15]),
                             b"can i haz cheezburger",
                             bytes([0x00, 0x0d]),
                             b"hello I'm dog",
                             bytes([0x00, 0x00, 0x00, 0x1b]),
                             b"I took an arrow in the knee",
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeySendKeys.__len__
        """

        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = b"can i haz cheezburger"
        signature = b"hello I'm dog"
        certificate_chain = b"I took an arrow in the knee"

        inst = DRKeySendKeys.from_values(session_id, cipher, signature,
                                         create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = certificate_chain

        ntools.eq_(len(inst), 16 + 2 + len(cipher) + 2 + len(signature) +
                   4 + len(certificate_chain))


class TestDRKeyAcknowledgeKeys(object):
    """
    Unit tests for lib.opt.drkey.DRKeyAcknowledgeKeys
    """
    @patch("lib.opt.drkey.CertificateChain")
    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.opt.drkey.DRKeyAcknowledgeKeys._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = (b"session_id",
                                bytes([0x00, 0x0a]),
                                b"cipher",
                                bytes([0x00, 0x0b]),
                                b"signature",
                                bytes([0x00, 0x00, 0x00, 0x0c]),
                                b"certificate_chain",
                                )
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeyAcknowledgeKeys()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        ntools.eq_(inst.session_id, b"session_id")
        ntools.eq_(inst.cipher_length, 0x0a)
        ntools.eq_(inst.cipher, b"cipher")
        ntools.eq_(inst.sign_length, 0x0b)
        ntools.eq_(inst.signature, b"signature")
        ntools.eq_(inst.cc_length, 0x0c)
        ntools.eq_(inst.certificate_chain, "certificate_chain")

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeyAcknowledgeKeys.pack
        """
        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        # A Haiku for you
        cipher = b"no, no, no, no, no"
        signature = b"no, no, no, no, no, no, no"
        cert_chain = b"no, no, no, no, no"

        inst = DRKeyAcknowledgeKeys.from_values(session_id, cipher, signature,
                                                create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = cert_chain
        expected = b"".join([session_id,
                             bytes([0x00, 0x12]),
                             cipher,
                             bytes([0x00, 0x1a]),
                             signature,
                             bytes([0x00, 0x00, 0x00, 0x12]),
                             cert_chain,
                             ])

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeyAcknowledgeKeys.__len__
        """

        session_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = b"yes, yes, yes, yes, yes"
        signature = b"yes, yes, yes, yes, yes, yes, yes"
        cert_chain = b"yes, yes, yes, yes, yes"

        inst = DRKeyAcknowledgeKeys.from_values(session_id, cipher, signature,
                                                create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = cert_chain

        ntools.eq_(len(inst), 16 + 2 + len(cipher) + 2 + len(signature) +
                   4 + len(cert_chain))


class TestDRKeyRequestCertChain(object):
    """
    Unit tests for lib.opt.drkey.DRKeyRequestCertChain
    """

    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw):
        """
        Unit tests for lib.opt.drkey.DRKeyRequestCertChain._parse
        """

        data = create_mock(["pop"])
        data.pop.side_effect = b"you should not see this"

        inst = DRKeyRequestCertChain()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 0)

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeyRequestCertChain.pack
        """
        inst = DRKeyRequestCertChain()
        expected = b""

        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeyRequestCertChain.__len__
        """
        inst = DRKeyRequestCertChain()
        # Call
        ntools.eq_(len(inst), 0)


class TestDRKeyReplyCertChain(object):
    """
    Unit tests for lib.opt.drkey.DRKeyReplyCertChain
    """

    @patch("lib.opt.drkey.CertificateChain")
    @patch("lib.opt.drkey.Raw", autospec=True)
    def test_parse(self, raw, cert_chain):
        """
        Unit tests for lib.opt.drkey.DRKeyReplyCertChain._parse
        """

        data = create_mock(["pop"])
        data.pop.return_value = b"CertChain"
        raw.return_value = data
        cert_chain.side_effect = lambda x: x

        inst = DRKeyReplyCertChain()
        inst._parse("data")
        ntools.assert_true(raw.call_count == 1)
        data.pop.assert_called_once_with()
        ntools.eq_(inst.certificate_chain, "CertChain")

    def test_pack(self):
        """
        Unit tests for lib.opts.drkey.DRKeyReplyCertChain.pack
        """
        cert_chain = bytes.fromhex("ffeeddccbbaa99887766554433221100")

        inst = DRKeyReplyCertChain.from_values(create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = cert_chain

        expected = b"".join([cert_chain])
        ntools.eq_(inst.pack(), expected)

    def test_len(self):
        """
        Unit tests for lib.opt.drkey.DRKeyReplyCertChain.__len__
        """
        inst = DRKeyReplyCertChain.from_values(create_mock(["pack"]))
        inst.certificate_chain.pack.return_value = bytes(32)
        # Call
        ntools.eq_(len(inst), 32)


class TestParseDRKeyPayload(object):
    """
    Unit tests for lib.opt.drkey.parse_drkey_payload
    """
    @patch("lib.opt.drkey._TYPE_MAP", new_callable=dict)
    def _check_supported(self, type_, type_map):
        type_map[0] = create_mock(), 20
        type_map[1] = create_mock(), None
        handler, len_ = type_map[type_]
        data = create_mock(["pop"])
        # Call
        ntools.eq_(parse_drkey_payload(type_, data), handler.return_value)
        # Tests
        data.pop.assert_called_once_with(len_)
        handler.assert_called_once_with(data.pop.return_value)

    def test_supported(self):
        for type_ in (0, 1):
            yield self._check_supported, type_

    def test_unsupported(self):
        # Call
        ntools.assert_raises(SCIONParseError, parse_drkey_payload,
                             "unknown type", "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
