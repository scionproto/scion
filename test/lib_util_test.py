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
:mod:`lib_util_test` --- lib.util tests
=====================================================
"""
# Stdlib
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.defines import TOPOLOGY_PATH
from lib.util import (
    _get_isd_prefix,
    CERT_DIR,
    ENC_KEYS_DIR,
    get_cert_chain_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    handle_signals,
    read_file,
    SIG_KEYS_DIR,
    sleep_interval,
    timed,
    trace,
    write_file,
)


class TestGetIsdPrefix(object):
    """
    Unit tests for lib.util._get_isd_prefix
    """
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join):
        join.return_value = "data1"
        ntools.eq_(_get_isd_prefix("data2"), "data1")
        join.assert_called_once_with("data2", 'ISD')


class TestGetCertChainFilePath(object):
    """
    Unit tests for lib.get_cert_chain_file_path
    """
    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join, gip):
        gip.return_value = "data1"
        join.return_value = "data2"
        ntools.eq_(get_cert_chain_file_path(1, 2, 3, 4, 5, 6), "data2")
        gip.assert_called_once_with(6)
        join.assert_called_once_with("data11", CERT_DIR, 'AD{}'.format(2),
                                     'ISD:{}-AD:{}-V:{}.crt'.format(3, 4, 5))

    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_len(self, join, gip):
        join.return_value = "data"
        ntools.eq_(get_cert_chain_file_path(1, 2, 3, 4, 5), "data")
        gip.assert_called_once_with(TOPOLOGY_PATH)


class TestGetTRCFilePath(object):
    """
    Unit tests for lib.get_trc_file_path
    """
    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join, gip):
        gip.return_value = "data1"
        join.return_value = "data2"
        ntools.eq_(get_trc_file_path(1, 2, 3, 4, 5), "data2")
        gip.assert_called_once_with(5)
        join.assert_called_once_with("data11", CERT_DIR, 'AD{}'.format(2),
                                     'ISD:{}-V:{}.crt'.format(3, 4))

    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_len(self, join, gip):
        join.return_value = "data"
        ntools.eq_(get_trc_file_path(1, 2, 3, 4), "data")
        gip.assert_called_once_with(TOPOLOGY_PATH)


class TestGetSigKeyFilePath(object):
    """
    Unit tests for lib.get_sig_key_file_path
    """
    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join, gip):
        gip.return_value = "data1"
        join.return_value = "data2"
        ntools.eq_(get_sig_key_file_path(1, 2, 3), "data2")
        gip.assert_called_once_with(3)
        join.assert_called_once_with("data11", SIG_KEYS_DIR,
                                     'ISD:{}-AD:{}.key'.format(1, 2))

    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_len(self, join, gip):
        join.return_value = "data"
        ntools.eq_(get_sig_key_file_path(1, 2), "data")
        gip.assert_called_once_with(TOPOLOGY_PATH)


class TestGetEncKeyFilePath(object):
    """
    Unit tests for lib.get_enc_key_file_path
    """
    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join, gip):
        gip.return_value = "data1"
        join.return_value = "data2"
        ntools.eq_(get_enc_key_file_path(1, 2, 3), "data2")
        gip.assert_called_once_with(3)
        join.assert_called_once_with("data11", ENC_KEYS_DIR,
                                     'ISD:{}-AD:{}.key'.format(1, 2))

    @patch("lib.util._get_isd_prefix", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_len(self, join, gip):
        join.return_value = "data"
        ntools.eq_(get_enc_key_file_path(1, 2), "data")
        gip.assert_called_once_with(TOPOLOGY_PATH)


class TestReadFile(object):
    """
    Unit tests for lib.util.read_file
    """
    @patch("lib.util.open", autospec=True)
    def test_basic

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
