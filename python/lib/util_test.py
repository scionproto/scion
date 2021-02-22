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
import unittest
from unittest.mock import patch, mock_open

# External packages
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


class TestWriteFile(unittest.TestCase):
    """
    Unit tests for lib.util.write_file
    """
    @patch("python.lib.util.os.rename", autospec=True)
    @patch.object(builtins, 'open', mock_open())
    @patch("python.lib.util.os.makedirs", autospec=True)
    @patch("python.lib.util.os.path.dirname", autospec=True)
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

    @patch("python.lib.util.os.makedirs", autospec=True)
    def test_mkdir_error(self, mkdir):
        mkdir.side_effect = FileNotFoundError
        # Call
        with self.assertRaises(SCIONIOError):
            write_file("File_Path", "Text")

    @patch.object(builtins, 'open', mock_open())
    @patch("python.lib.util.os.makedirs", autospec=True)
    def test_file_error(self, mkdir):
        builtins.open.side_effect = PermissionError
        # Call
        with self.assertRaises(SCIONIOError):
            write_file("File_Path", "Text")

    @patch("python.lib.util.os.rename", autospec=True)
    @patch.object(builtins, 'open', mock_open())
    @patch("python.lib.util.os.makedirs", autospec=True)
    def test_rename_error(self, mkdir, rename):
        rename.side_effect = PermissionError
        # Call
        with self.assertRaises(SCIONIOError):
            write_file("File_Path", "Text")


class TestLoadYAMLFile(unittest.TestCase):
    """
    Unit tests for lib.util.load_yaml_file
    """
    @patch.object(builtins, 'open', mock_open())
    def test_file_error(self):
        builtins.open.side_effect = IsADirectoryError
        with self.assertRaises(SCIONIOError):
            load_yaml_file("File_Path")

    @patch.object(builtins, 'open', mock_open())
    def test_yaml_error(self):
        with patch("python.lib.util.yaml.load", autospec=True) as loader:
            loader.side_effect = yaml.scanner.ScannerError
            with self.assertRaises(SCIONYAMLError):
                load_yaml_file("File_Path")


if __name__ == "__main__":
    unittest.main()
