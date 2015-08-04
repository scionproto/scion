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
import builtins
from unittest.mock import patch, call, mock_open, MagicMock

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.defines import TOPOLOGY_PATH
from lib.errors import (
    SCIONIOError,
    SCIONIndexError,
    SCIONJSONError,
    SCIONParseError,
    SCIONTypeError,
)
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
    load_json_file,
    Raw,
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


class TestReadFile(object):
    """
    Unit tests for lib.util.read_file
    """
    @patch.object(builtins, 'open',
                  mock_open(read_data="file contents"))
    def test_basic(self):
        ntools.eq_(read_file("File_Path"), "file contents")
        builtins.open.assert_called_once_with("File_Path")
        builtins.open.return_value.read.assert_called_once_with()

    @patch.object(builtins, 'open', mock_open())
    def test_error(self):
        builtins.open.side_effect = IsADirectoryError
        ntools.assert_raises(SCIONIOError, read_file, "File_Path")


class TestWriteFile(object):
    """
    Unit tests for lib.util.write_file
    """
    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_basic(self, dirname, makedirs):
        dirname.return_value = "Dir_Name"
        write_file("File_Path", "Text")
        dirname.assert_called_once_with("File_Path")
        makedirs.assert_called_once_with("Dir_Name", exist_ok=True)
        builtins.open.assert_called_once_with("File_Path", 'w')
        builtins.open.return_value.write.assert_called_once_with("Text")

    @patch("lib.util.os.makedirs", autospec=True)
    def test_mkdir_error(self, mkdir):
        mkdir.side_effect = FileNotFoundError
        ntools.assert_raises(SCIONIOError, write_file, "File_Path", "Text")

    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.os.makedirs", autospec=True)
    def test_file_error(self, mkdir):
        builtins.open.side_effect = PermissionError
        ntools.assert_raises(SCIONIOError, write_file, "File_Path", "Text")


class TestLoadJSONFile(object):
    """
    Unit tests for lib.util.load_json_file
    """
    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.json.load", autospec=True)
    def test_basic(self, json_load):
        json_load.return_value = "JSON dict"
        ntools.eq_(load_json_file("File_Path"), "JSON dict")
        builtins.open.assert_called_once_with("File_Path")
        json_load.assert_called_once_with(builtins.open.return_value)

    @patch.object(builtins, 'open', mock_open())
    def test_file_error(self):
        builtins.open.side_effect = IsADirectoryError
        ntools.assert_raises(SCIONIOError, load_json_file, "File_Path")

    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.json.load", autospec=True)
    def _check_json_error(self, excp, json_load):
        json_load.side_effect = excp
        ntools.assert_raises(SCIONJSONError, load_json_file, "File_Path")

    def test_json_error(self):
        for excp in ValueError, KeyError, TypeError:
            yield self._check_json_error, excp


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


class TestRawInit(object):
    """
    Unit tests for lib.util.Raw.__init__
    """
    @patch("lib.util.Raw.check_len", autospec=True)
    @patch("lib.util.Raw.check_type", autospec=True)
    def test_basic(self, check_type, check_len):
        # Call
        r = Raw(b"data")
        # Tests
        ntools.eq_(r._data, b"data")
        ntools.eq_(r._desc, "")
        ntools.eq_(r._len, None)
        ntools.eq_(r._min, False)
        ntools.eq_(r._offset, 0)
        check_type.assert_called_once_with(r)
        check_len.assert_called_once_with(r)

    @patch("lib.util.Raw.check_len", autospec=True)
    @patch("lib.util.Raw.check_type", autospec=True)
    def test_full(self, check_type, check_len):
        # Call
        r = Raw(b"data", "Test data", len_=45, min_=True)
        # Tests
        ntools.eq_(r._data, b"data")
        ntools.eq_(r._desc, "Test data")
        ntools.eq_(r._len, 45)
        ntools.eq_(r._min, True)


class TestRawCheckType(object):
    """
    Unit tests for lib.util.Raw.check_type
    """
    def test_bytes(self):
        inst = MagicMock(spec_set=["_data"])
        inst._data = b"asdf"
        Raw.check_type(inst)

    def test_error(self):
        inst = MagicMock(spec_set=["_data", "_desc"])
        inst._data = "asdf"
        ntools.assert_raises(SCIONTypeError, Raw.check_type, inst)


class TestRawCheckLen(object):
    """
    Unit tests for lib.util.Raw.check_len
    """
    def test_no_len(self):
        inst = MagicMock(spec_set=["_len"])
        inst._len = None
        Raw.check_len(inst)

    def test_min(self):
        inst = MagicMock(spec_set=["_data", "_len", "_min"])
        inst._len = 4
        inst._data = "abcde"
        Raw.check_len(inst)

    def test_basic(self):
        inst = MagicMock(spec_set=["_data", "_len", "_min"])
        inst._min = False
        inst._len = 4
        inst._data = "abcd"
        Raw.check_len(inst)

    def test_min_error(self):
        inst = MagicMock(spec_set=["_data", "_desc", "_len", "_min"])
        inst._len = 4
        inst._data = "abc"
        ntools.assert_raises(SCIONParseError, Raw.check_len, inst)

    def test_basic_error(self):
        inst = MagicMock(spec_set=["_data", "_desc", "_len", "_min"])
        inst._min = False
        inst._len = 4
        inst._data = "abc"
        ntools.assert_raises(SCIONParseError, Raw.check_len, inst)


class TestRawGet(object):
    """
    Unit tests for lib.util.Raw.get
    """
    def _check(self, count, start_off, expected):
        # Setup
        r = Raw(b"data")
        r._offset = start_off
        # Call
        data = r.get(count)
        # Tests
        ntools.eq_(data, expected)

    def test(self):
        for count, start_off, expected in (
            (None, 0, b"data"),
            (None, 2, b"ta"),
            (1, 0, 0x64),  # "d"
            (1, 2, 0x74),  # "t"
            (2, 0, b"da"),
            (2, 2, b"ta"),
        ):
            yield self._check, count, start_off, expected

    def test_bounds_true(self):
        # Setup
        r = Raw(b"data")
        # Call
        ntools.assert_raises(SCIONIndexError, r.get, 100)

    def test_bounds_false(self):
        # Setup
        r = Raw(b"data")
        # Call
        r.get(100, bounds=False)


class TestRawPop(object):
    """
    Unit tests for lib.util.Raw.pop
    """
    @patch("lib.util.Raw.get", autospec=True)
    def _check(self, pop, start_off, end_off, get):
        # Setup
        r = Raw(b"data")
        r._offset = start_off
        # Call
        r.pop(pop)
        # Tests
        get.assert_called_once_with(r, pop, True)
        ntools.eq_(r._offset, end_off)

    def test(self):
        for pop, start_off, end_off in (
            (None, 0, 4),
            (None, 2, 4),
            (1, 0, 1),
            (1, 2, 3),
            (2, 0, 2),
            (3, 2, 4),
        ):
            yield self._check, pop, start_off, end_off


class TestRawOffset(object):
    """
    Unit tests for lib.util.Raw.offset
    """
    def test(self):
        # Setup
        r = Raw(b"data")
        r._offset = 3
        # Call
        ntools.eq_(r.offset(), 3)


class TestRawLen(object):
    """
    Unit tests for lib.util.Raw.__len__
    """
    def _check(self, start_off, expected):
        # Setup
        r = Raw(b"data")
        r._offset = start_off
        # Check
        ntools.eq_(len(r), expected)

    def test(self):
        for start_off, expected in (
            (0, 4), (1, 3), (3, 1), (4, 0), (10, 0),
        ):
            yield self._check, start_off, expected

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
