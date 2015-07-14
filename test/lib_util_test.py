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
from unittest.mock import patch, call, mock_open, MagicMock

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
    SCIONTime,
    SIG_KEYS_DIR,
    sleep_interval,
    timed,
    trace,
    TRACE_DIR,
    update_dict,
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
        join.assert_any_call("data2", 'ISD')


@patch("lib.util.os.path.join", autospec=True)
@patch("lib.util._get_isd_prefix", autospec=True)
class TestGetCertChainFilePath(object):
    """
    Unit tests for lib.util.get_cert_chain_file_path
    """
    def test_basic(self, isd_prefix, join):
        isd_prefix.return_value = "isd_prefix"
        join.return_value = "data2"
        ntools.eq_(get_cert_chain_file_path(1, 2, 3, 4, 5, 6), "data2")
        isd_prefix.assert_called_once_with(6)
        join.assert_any_call("isd_prefix1", CERT_DIR, 'AD2',
                             'ISD:3-AD:4-V:5.crt')

    def test_len(self, isd_prefix, join):
        get_cert_chain_file_path(1, 2, 3, 4, 5)
        isd_prefix.assert_called_once_with(TOPOLOGY_PATH)


@patch("lib.util.os.path.join", autospec=True)
@patch("lib.util._get_isd_prefix", autospec=True)
class TestGetTRCFilePath(object):
    """
    Unit tests for lib.util.get_trc_file_path
    """
    def test_basic(self, isd_prefix, join):
        isd_prefix.return_value = "isd_prefix"
        join.return_value = "data2"
        ntools.eq_(get_trc_file_path(1, 2, 3, 4, 5), "data2")
        isd_prefix.assert_called_once_with(5)
        join.assert_any_call("isd_prefix1", CERT_DIR, 'AD2', 'ISD:3-V:4.crt')

    def test_len(self, isd_prefix, join):
        get_trc_file_path(1, 2, 3, 4)
        isd_prefix.assert_called_once_with(TOPOLOGY_PATH)


@patch("lib.util.os.path.join", autospec=True)
@patch("lib.util._get_isd_prefix", autospec=True)
class TestGetSigKeyFilePath(object):
    """
    Unit tests for lib.util.et_sig_key_file_path
    """
    def test_basic(self, isd_prefix, join):
        isd_prefix.return_value = "isd_prefix"
        join.return_value = "data2"
        ntools.eq_(get_sig_key_file_path(1, 2, 3), "data2")
        isd_prefix.assert_called_once_with(3)
        join.assert_any_call("isd_prefix1", SIG_KEYS_DIR, 'ISD:1-AD:2.key')

    def test_len(self, isd_prefix, join):
        get_sig_key_file_path(1, 2)
        isd_prefix.assert_called_once_with(TOPOLOGY_PATH)


@patch("lib.util.os.path.join", autospec=True)
@patch("lib.util._get_isd_prefix", autospec=True)
class TestGetEncKeyFilePath(object):
    """
    Unit tests for lib.util.get_enc_key_file_path
    """
    def test_basic(self, isd_prefix, join):
        isd_prefix.return_value = "isd_prefix"
        join.return_value = "data2"
        ntools.eq_(get_enc_key_file_path(1, 2, 3), "data2")
        isd_prefix.assert_called_once_with(3)
        join.assert_any_call("isd_prefix1", ENC_KEYS_DIR, 'ISD:1-AD:2.key')

    def test_len(self, isd_prefix, join):
        get_enc_key_file_path(1, 2)
        isd_prefix.assert_called_once_with(TOPOLOGY_PATH)


@patch("lib.util.os.path.exists", autospec=True)
class TestReadFile(object):
    """
    Unit tests for lib.util.read_file
    """
    def test_basic(self, exists):
        exists.return_value = True
        with patch('lib.util.open', mock_open(read_data="file contents"),
                   create=True) as open_f:
            ntools.eq_(read_file("File_Path"), "file contents")
            exists.assert_called_once_with("File_Path")
            open_f.assert_called_once_with("File_Path", 'r')
            open_f.return_value.read.assert_called_once_with()

    def test_not_exist(self, exists):
        exists.return_value = False
        ntools.eq_(read_file("File_Path"), '')


class TestWriteFile(object):
    """
    Unit tests for lib.util.write_file
    """
    @patch("lib.util.os.path.exists", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_basic(self, dirname, exists):
        dirname.return_value = "Dir_Name"
        exists.return_value = True
        with patch('lib.util.open', mock_open(),
                   create=True) as open_f:
            write_file("File_Path", "Text")
            dirname.assert_called_once_with("File_Path")
            exists.assert_called_once_with("Dir_Name")
            open_f.assert_called_once_with("File_Path", 'w')
            open_f.return_value.write.assert_called_once_with("Text")

    @patch("builtins.open", autospec=True)
    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.exists", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_not_exist(self, dirname, exists, mkdir, open_f):
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

    def test_not_present(self):
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
        join.assert_any_call(TRACE_DIR, "3.trace.html")
        trace_start.assert_called_once_with("Path")


class TestTimed(object):
    """
    Unit tests for lib.util.timed
    """
    @timed(1.0)
    def wrapped(self):
        pass

    @patch("lib.util.logging.warning", autospec=True)
    @patch("lib.util.time.time", autospec=True)
    def test_basic(self, time_, warning):
        time_.side_effect = [0, 0.1]
        self.wrapped()
        ntools.eq_(warning.call_count, 0)

    @patch("lib.util.logging.warning", autospec=True)
    @patch("lib.util.time.time", autospec=True)
    def test_limit_exceeded(self, time_, warning):
        time_.side_effect = [0, 2.0]
        self.wrapped()
        ntools.eq_(warning.call_count, 1)


@patch("lib.util.time.sleep", autospec=True)
@patch("lib.util.time.time", autospec=True)
@patch("lib.util.logging.warning", autospec=True)
class TestSleepInterval(object):
    """
    Unit tests for lib.util.sleep_interval
    """
    def test_basic(self, warning, time_, sleep_):
        time_.return_value = 3
        sleep_interval(3, 2, "desc")
        time_.assert_called_once_with()
        ntools.eq_(warning.call_count, 0)
        sleep_.assert_called_once_with(2)

    def test_zero(self, warning, time_, sleep_):
        time_.return_value = 3
        sleep_interval(0, 2, "desc")
        ntools.eq_(warning.call_count, 1)
        sleep_.assert_called_once_with(0)


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
    @patch("lib.util.sys.exit", autospec=True)
    @patch("lib.util.logging.info", autospec=True)
    def test_basic(self, info, exit):
        _signal_handler(1, 2)
        info.assert_called_once_with("Received %s", _SIG_MAP[1])
        exit.assert_called_once_with(0)


class TestSCIONTimeGetTime(object):
    """
    Unit tests for lib.util.SCIONTime.get_time
    """
    @patch("lib.util.time.time", autospec=True)
    def test_basic(self, mock_time):
        t = SCIONTime.get_time()
        mock_time.assert_called_once_with()
        ntools.eq_(t, mock_time.return_value)

    @patch("lib.util.SCIONTime._custom_time", spec_set=[],
           new_callable=MagicMock)
    def test_custom_time(self, custom_time):
        t = SCIONTime.get_time()
        ntools.eq_(t, custom_time.return_value)
        custom_time.assert_called_once_with()


class TestSCIONTimeSetTimeMethod(object):
    """
    Unit tests for lib.util.SCIONTime.set_time_method
    """
    class MockSCIONTime(SCIONTime):
        pass

    def setUp(self):
        self.MockSCIONTime._custom_time = 'before'

    def tearDown(self):
        self.MockSCIONTime._custom_time = None

    def test(self):
        self.MockSCIONTime.set_time_method('time_method')
        ntools.eq_(self.MockSCIONTime._custom_time, 'time_method')


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
