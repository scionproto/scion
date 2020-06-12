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
from unittest.mock import patch, mock_open

# External packages
import nose
import nose.tools as ntools
import yaml

# SCION
from python.lib.errors import (
    SCIONIOError,
    SCIONYAMLError,
)
from python.lib.util import (
    load_yaml_file,
    write_file,
)


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


class Loader(object):
    """
    Helper class for load_yaml_file tests.
    """
    @patch.object(builtins, 'open', mock_open())
    def _file_error(self, target):
        builtins.open.side_effect = IsADirectoryError
        ntools.assert_raises(SCIONIOError, target, "File_Path")

    @patch.object(builtins, 'open', mock_open())
    def _check_loader_error(self, target, loader_path, excp, expected):
        with patch(loader_path, autospec=True) as loader:
            loader.side_effect = excp
            ntools.assert_raises(expected, target, "File_Path")


class TestLoadYAMLFile(Loader):
    """
    Unit tests for lib.util.load_yaml_file
    """
    def test_file_error(self):
        self._file_error(load_yaml_file)

    def test_json_error(self):
        for excp in (yaml.scanner.ScannerError, ):
            yield (
                self._check_loader_error, load_yaml_file, "lib.util.yaml.load",
                excp, SCIONYAMLError,
            )


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
