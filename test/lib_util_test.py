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
:mod:`lib_util_test` --- lib.util unit tests
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
    _SIG_MAP,
    _signal_handler,
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
    TRACE_DIR,
    update_dict,
    write_file
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
    Unit tests for lib.util.get_cert_chain_file_path
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
    Unit tests for lib.util.get_trc_file_path
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
    Unit tests for lib.util.et_sig_key_file_path
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
    Unit tests for lib.util.get_enc_key_file_path
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
    @patch("lib.util.os.path.exists", autospec=True)
    @patch("builtins.open", autospec=True)
    def test_basic(self, open_f, exists):
        exists.return_value = True
        file_handler = MagicMock(spec_set=['read'])
        file_handler.read.return_value = "Text"
        with_init = MagicMock(spec_set=['__enter__', '__exit__'])
        with_init.__enter__.return_value = file_handler
        open_f.return_value = with_init
        ntools.eq_(read_file("File_Path"), "Text")
        exists.assert_called_once_with("File_Path")
        open_f.assert_called_once_with("File_Path", 'r')
        with_init.__enter__.assert_called_once_with()
        file_handler.read.assert_called_once_with()
        with_init.__exit__.assert_called_once_with(None, None, None)

    @patch("lib.util.os.path.exists", autospec=True)
    def test_not_exist(self, exists):
        exists.return_value = False
        ntools.eq_(read_file("File_Path"), '')


class TestWriteFile(object):
    """
    Unit tests for lib.util.write_file
    """
    @patch("lib.util.os.path.dirname", autospec=True)
    @patch("lib.util.os.path.exists", autospec=True)
    @patch("builtins.open", autospec=True)
    def test_basic(self, open_f, exists, dirname):
        dirname.return_value = "Dir_Name"
        exists.return_value = True
        file_handler = MagicMock(spec_set=['write'])
        with_init = MagicMock(spec_set=['__enter__', '__exit__'])
        with_init.__enter__.return_value = file_handler
        open_f.return_value = with_init
        write_file("File_Path", "Text")
        dirname.assert_called_once_with("File_Path")
        exists.assert_called_once_with("Dir_Name")
        open_f.assert_called_once_with("File_Path", 'w')
        with_init.__enter__.assert_called_once_with()
        file_handler.write.assert_called_once_with("Text")
        with_init.__exit__.assert_called_once_with(None, None, None)

    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    @patch("lib.util.os.path.exists", autospec=True)
    @patch("builtins.open", autospec=True)
    def test_not_exist(self, open_f, exists, dirname, mkdir):
        dirname.return_value = "Dir_Name"
        exists.return_value = False
        write_file("File_Path", "Text")
        dirname.assert_has_calls([call("File_Path"), call("File_Path")])
        mkdir.assert_called_once_with("Dir_Name")


class TestUpdateDict(object):
    """
    Unit tests for lib.util.update_dict
    """
    def test_basic(self):
        dictionary = {}
        dictionary['key'] = [1, 2]
        update_dict(dictionary, 'key', [3], 2)
        ntools.eq_(dictionary['key'], [2, 3])

    def test_len(self):
        dictionary = {}
        dictionary['key'] = [1, 2]
        update_dict(dictionary, 'key', [3])
        ntools.eq_(dictionary['key'], [1, 2, 3])

    def not_present(self):
        dictionary = {}
        update_dict(dictionary, 'key', [1, 2, 3, 4], 2)
        ntools.eq_(dictionary['key'], [3, 4])


class TestTrace(object):
    """
    Unit tests for lib.util.trace
    """
    @patch("lib.util.trace_start", autospec=True)
    @patch("lib.util.os.path.join", autospec=True)
    def test_basic(self, join, trace_start):
        join.return_value = "Path"
        trace(3)
        join.assert_called_once_with(TRACE_DIR, "3.trace.html")
        trace_start.assert_called_once_with("Path")


class TestSleepInterval(object):
    """
    Unit tests for lib.util.sleep_interval
    """
    @patch("lib.util.time.sleep", autospec=True)
    @patch("lib.util.time.time", autospec=True)
    def test_basic(self, time, sleep):
        time.return_value = 0
        sleep_interval(3, 4, 5)
        time.assert_called_once_with()
        sleep.assert_called_once_with(7)

    @patch("lib.util.time.sleep", autospec=True)
    @patch("lib.util.time.time", autospec=True)
    def test_zero(self, time, sleep):
        time.return_value = 8
        sleep_interval(3, 4, 5)
        sleep.assert_called_once_with(0)


class TestHandleSignals(object):
    """
    Unit tests for lib.util.handle_signals
    """
    @patch("lib.util.signal.signal", autospec=True)
    def test_basic(self, sgnl):
        handle_signals()
        sgnl.assert_has_calls([call(sig, _signal_handler) for sig in
                                                              _SIG_MAP.keys()])


class TestSignalHandler(object):
    """
    Unit tests for lib.util._signal_handler
    """
    @patch("lib.util.logging.info", autospec=True)
    @patch("lib.util.sys.exit", autospec=True)
    def test_basic(self, exit, info):
        _signal_handler(1, 2)
        info.assert_called_once_with("Received %s", _SIG_MAP[1])
        exit.assert_called_once_with(0)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
