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
from signal import SIGINT, SIGQUIT, SIGTERM
from unittest.mock import patch, call, mock_open, MagicMock

# External packages
import nose
import nose.tools as ntools
import yaml

# SCION
from lib.errors import (
    SCIONIOError,
    SCIONIndexError,
    SCIONJSONError,
    SCIONYAMLError,
    SCIONParseError,
    SCIONTypeError,
)
from lib.util import (
    Raw,
    SCIONTime,
    TRACE_DIR,
    _SIG_MAP,
    _signal_handler,
    calc_padding,
    copy_file,
    handle_signals,
    load_json_file,
    load_yaml_file,
    read_file,
    sleep_interval,
    trace,
    update_dict,
    write_file,
)


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
    @patch("lib.util.os.rename", autospec=True)
    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_basic(self, dirname, makedirs, rename):
        dirname.return_value = "Dir_Name"
        # Call
        write_file("File_Path", "Text")
        # Tests
        dirname.assert_called_once_with("File_Path")
        makedirs.assert_called_once_with("Dir_Name", exist_ok=True)
        builtins.open.assert_called_once_with("File_Path.new", 'w')
        builtins.open.return_value.write.assert_called_once_with("Text")
        rename.assert_called_once_with("File_Path.new", "File_Path")

    @patch("lib.util.os.makedirs", autospec=True)
    def test_mkdir_error(self, mkdir):
        mkdir.side_effect = FileNotFoundError
        # Call
        ntools.assert_raises(SCIONIOError, write_file, "File_Path", "Text")

    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.os.makedirs", autospec=True)
    def test_file_error(self, mkdir):
        builtins.open.side_effect = PermissionError
        # Call
        ntools.assert_raises(SCIONIOError, write_file, "File_Path", "Text")

    @patch("lib.util.os.rename", autospec=True)
    @patch.object(builtins, 'open', mock_open())
    @patch("lib.util.os.makedirs", autospec=True)
    def test_rename_error(self, mkdir, rename):
        rename.side_effect = PermissionError
        # Call
        ntools.assert_raises(SCIONIOError, write_file, "File_Path", "Text")


class TestCopyFile(object):
    """
    Unit tests for lib.util.copy_file
    """
    @patch("lib.util.shutil.copyfile", autospec=True)
    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_basic(self, dirname, mkdirs, cpfile):
        # Call
        copy_file("a", "b")
        # Tests
        mkdirs.assert_called_once_with(dirname.return_value, exist_ok=True)
        cpfile.assert_called_once_with("a", "b")

    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_mkdir_error(self, dirname, mkdirs):
        mkdirs.side_effect = PermissionError
        # Call
        ntools.assert_raises(SCIONIOError, copy_file, "a", "b")

    @patch("lib.util.shutil.copyfile", autospec=True)
    @patch("lib.util.os.makedirs", autospec=True)
    @patch("lib.util.os.path.dirname", autospec=True)
    def test_copy_error(self, dirname, mkdirs, cpfile):
        cpfile.side_effect = PermissionError
        # Call
        ntools.assert_raises(SCIONIOError, copy_file, "a", "b")


class Loader(object):
    """
    Helper class for load_json_file and load_yaml_file tests.
    """
    def _basic(self, target, loader):
        loader.return_value = "loader dict"
        with patch.object(builtins, 'open', mock_open()) as open_:
            ntools.eq_(target("File_Path"), "loader dict")
            open_.assert_called_once_with("File_Path")
            loader.assert_called_once_with(open_.return_value)

    @patch.object(builtins, 'open', mock_open())
    def _file_error(self, target):
        builtins.open.side_effect = IsADirectoryError
        ntools.assert_raises(SCIONIOError, target, "File_Path")

    @patch.object(builtins, 'open', mock_open())
    def _check_loader_error(self, target, loader_path, excp, expected):
        with patch(loader_path, autospec=True) as loader:
            loader.side_effect = excp
            ntools.assert_raises(expected, target, "File_Path")


class TestLoadJSONFile(Loader):
    """
    Unit tests for lib.util.load_json_file
    """
    @patch("lib.util.json.load", autospec=True)
    def test_basic(self, loader):
        self._basic(load_json_file, loader)

    def test_file_error(self):
        self._file_error(load_json_file)

    def test_json_error(self):
        for excp in ValueError, KeyError, TypeError:
            yield (
                self._check_loader_error, load_json_file, "lib.util.json.load",
                excp, SCIONJSONError,
            )


class TestLoadYAMLFile(Loader):
    """
    Unit tests for lib.util.load_yaml_file
    """
    @patch("lib.util.yaml.load", autospec=True)
    def test_basic(self, loader):
        self._basic(load_yaml_file, loader)

    def test_file_error(self):
        self._file_error(load_yaml_file)

    def test_json_error(self):
        for excp in (yaml.scanner.ScannerError, ):
            yield (
                self._check_loader_error, load_yaml_file, "lib.util.yaml.load",
                excp, SCIONYAMLError,
            )


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


class TestCalcPadding(object):
    """
    Unit tests for lib.util.calc_padding
    """
    def _check(self, length, expected):
        ntools.eq_(calc_padding(length, 8), expected)

    def test(self):
        for length, expected in (
            (0, 0), (1, 7), (7, 1),
            (8, 0), (9, 7), (15, 1),
            (16, 0),
        ):
            yield self._check, length, expected


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
    @patch("lib.util.atexit.register", autospec=True)
    def test_term(self, atexit, exit):
        exit.side_effect = SystemExit
        ntools.assert_raises(SystemExit, _signal_handler, SIGTERM, "")
        ntools.ok_(atexit.called)
        exit.assert_called_once_with(0)

    @patch("lib.util.sys.exit", autospec=True)
    @patch("lib.util.atexit.register", autospec=True)
    def test_int(self, atexit, exit):
        _signal_handler(SIGINT, "")
        exit.assert_called_once_with(1)

    @patch("lib.util.sys.exit", autospec=True)
    @patch("lib.util.atexit.register", autospec=True)
    def test_error(self, atexit, exit):
        _signal_handler(SIGQUIT, "")
        ntools.ok_(atexit.called)
        exit.assert_called_once_with(1)


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
