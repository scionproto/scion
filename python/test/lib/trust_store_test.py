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
:mod:`lib_trust_store_test` --- lib.trust_store unit tests
==========================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose.tools as ntools

# SCION
from lib.packet.scion_addr import ISD_AS
from lib.trust_store import TrustStore
from test.testcommon import create_mock


class TestTrustStoreGetTrc(object):
    """
    Unit tests for lib.trust_store.TrustStore.get_trc
    """
    def _init(self):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        inst._trcs[1] = [(1, 'trc1'), (3, 'trc3'), (0, 'trc0')]
        return inst

    def test_non_existing_isd(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_trc(2), None)

    def test_non_existing_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_trc(1, 2), None)

    def test_default_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_trc(1), 'trc3')

    def test_existing_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_trc(1, 1), 'trc1')


class TestTrustStoreGetCert(object):
    """
    Unit tests for lib.trust_store.TrustStore.get_cert
    """
    def _init(self):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        inst._certs["1-ff00:0:300"] = [(1, 'cert1'), (3, 'cert3'), (0, 'cert0')]
        return inst

    def test_non_existing_as(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_cert("2-ff00:0:322"), None)

    def test_non_existing_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_cert("1-ff00:0:300", 2), None)

    def test_default_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_cert("1-ff00:0:300"), 'cert3')

    def test_existing_version(self):
        inst = self._init()
        # Call
        ntools.eq_(inst.get_cert("1-ff00:0:300", 1), 'cert1')


class TestTrustStoreAddTrc(object):
    """
    Unit tests for lib.trust_store.TrustStore.add_trc
    """
    @patch("lib.trust_store.write_file", autospec=True)
    def test_add_unique_version(self, write_file):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        inst._trcs[1] = [(0, 'trc0'), (1, 'trc1')]
        trcs_before = inst._trcs[1][:]
        trc = create_mock(['get_isd_ver'])
        trc.get_isd_ver.return_value = (1, 2)
        # Call
        inst.add_trc(trc)
        # Tests
        ntools.eq_(inst._trcs[1], trcs_before + [(2, trc)])
        write_file.assert_called_once_with(
            "cache_dir/element_name-ISD1-V2.trc", str(trc))

    @patch("lib.trust_store.write_file", autospec=True)
    def test_add_non_unique_version(self, write_file):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        inst._trcs[1] = [(0, 'trc0'), (1, 'trc1')]
        trcs_before = inst._trcs[1][:]
        trc = create_mock(['get_isd_ver'])
        trc.get_isd_ver.return_value = (1, 1)
        # Call
        inst.add_trc(trc)
        # Tests
        ntools.eq_(inst._trcs[1], trcs_before)
        ntools.assert_false(write_file.called)


class TestTrustStoreAddCert(object):
    """
    Unit tests for lib.trust_store.TrustStore.add_cert
    """
    @patch("lib.trust_store.write_file", autospec=True)
    def test_add_unique_version(self, write_file):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        ia = ISD_AS("1-ff00:0:1")
        inst._certs[ia] = [(0, 'cert0'), (1, 'cert1')]
        certs_before = inst._certs[ia][:]
        cert = create_mock(['get_leaf_isd_as_ver'])
        cert.get_leaf_isd_as_ver.return_value = (ia, 2)
        # Call
        inst.add_cert(cert)
        # Tests
        ntools.eq_(inst._certs[ia], certs_before + [(2, cert)])
        write_file.assert_called_once_with(
            "cache_dir/element_name-ISD1-ASff00_0_1-V2.crt", str(cert))

    @patch("lib.trust_store.write_file", autospec=True)
    def test_add_non_unique_version(self, write_file):
        inst = TrustStore("conf_dir", "cache_dir", "element_name")
        ia = ISD_AS("1-ff00:0:1")
        inst._certs[ia] = [(0, 'cert0'), (1, 'cert1')]
        certs_before = inst._certs[ia][:]
        cert = create_mock(['get_leaf_isd_as_ver'])
        cert.get_leaf_isd_as_ver.return_value = (ia, 1)
        # Call
        inst.add_cert(cert)
        # Tests
        ntools.eq_(inst._certs[ia], certs_before)
        ntools.assert_false(write_file.called)
