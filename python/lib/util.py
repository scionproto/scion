# Copyright 2014 ETH Zurich
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
:mod:`util` --- SCION utilities
===============================

Various utilities for SCION functionality.
"""
# Stdlib
import os

# External packages
import json
import yaml

# SCION
from python.lib.errors import (
    SCIONIOError,
    SCIONYAMLError,
)


def write_file(file_path, text):
    """
    Write some text into a temporary file, creating its directory as needed, and
    then atomically move to target location.

    :param str file_path: the path to the file.
    :param str text: the file content.
    :raises:
        lib.errors.SCIONIOError: IO error occurred
    """
    # ":" is an illegal filename char on both windows and OSX, so disallow it globally to prevent
    # incompatibility.
    assert ":" not in file_path, file_path
    dir_ = os.path.dirname(file_path)
    try:
        os.makedirs(dir_, exist_ok=True)
    except OSError as e:
        raise SCIONIOError("Error creating '%s' dir: %s" %
                           (dir_, e.strerror)) from None
    tmp_file = file_path + ".new"
    try:
        with open(tmp_file, 'w') as f:
            f.write(text)
    except OSError as e:
        raise SCIONIOError("Error creating/writing to temp file '%s': %s" %
                           (file_path, e.strerror)) from None
    try:
        os.rename(tmp_file, file_path)
    except OSError as e:
        raise SCIONIOError("Error moving '%s' to '%s': %s" %
                           (tmp_file, file_path, e.strerror)) from None


def load_yaml_file(file_path):
    """
    Read and parse a YAML config file.

    :param str file_path: the path to the file.
    :returns: YAML data
    :rtype: dict
    :raises:
        lib.errors.SCIONIOError: error opening/reading from file.
        lib.errors.SCIONYAMLError: error parsing file.
    """
    try:
        with open(file_path) as f:
            return yaml.load(f, Loader=yaml.SafeLoader)
    except OSError as e:
        raise SCIONIOError("Error opening '%s': %s" %
                           (file_path, e.strerror)) from None
    except (yaml.scanner.ScannerError) as e:
        raise SCIONYAMLError("Error parsing '%s': %s" %
                             (file_path, e)) from None


def load_sciond_file(file_path):
    """
    Read a SCIOND addresses file.

    """
    with open(file_path) as f:
        return json.load(f)
