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
from datetime import datetime, timezone

# External packages
import json
import yaml

# SCION
from lib.errors import (
    SCIONIOError,
    SCIONIndexError,
    SCIONParseError,
    SCIONTypeError,
    SCIONYAMLError,
)

TRACE_DIR = 'traces'


def read_file(file_path):
    """
    Read and return contents of a file.

    :param str file_path: the path to the file.
    :returns: the file's contents.
    :rtype: str
    :raises:
        lib.errors.SCIONIOError: error opening/reading from file.
    """
    try:
        with open(file_path) as file_handler:
            return file_handler.read()
    except OSError as e:
        raise SCIONIOError("Unable to open '%s': %s" % (
            file_path, e.strerror)) from None


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


def iso_timestamp(ts):  # pragma: no cover
    """
    Format a unix timestamp as a UTC ISO 8601 format string
    (YYYY-MM-DD HH:MM:SS.mmmmmm+00:00)

    :param float ts: Seconds since the UNIX epoch.
    """
    return str(datetime.fromtimestamp(ts, tz=timezone.utc))


class Raw(object):
    """A class to wrap raw bytes objects."""
    def __init__(self, data, desc="", len_=None,
                 min_=False):  # pragma: no cover
        self._data = data
        self._desc = desc
        self._len = len_
        self._min = min_
        self._offset = 0
        self.check_type()
        self.check_len()

    def check_type(self):
        """
        Check that the data is a `bytes` instance. If not, raise an exception.

        :raises:
            lib.errors.SCIONTypeError: data is the wrong type
        """
        if not isinstance(self._data, bytes):
            raise SCIONTypeError(
                "Error parsing raw %s: Expected %s, got %s" %
                (self._desc, bytes, type(self._data)))

    def check_len(self):
        """
        Check that the data is of the expected length. If not, raise an
        exception.

        :raises:
            lib.errors.SCIONTypeError: data is the wrong length
        """
        if self._len is None:
            return
        if self._min:
            if len(self._data) >= self._len:
                return
            else:
                op = ">="
        elif len(self._data) == self._len:
            return
        else:
            op = "=="
        raise SCIONParseError(
            "Error parsing raw %s: Expected len %s %s, got %s" %
            (self._desc, op, self._len, len(self._data)))

    def get(self, n=None, bounds=True):
        """
        Return next elements from data.

        If `n` is not specified, return all remaining elements of data.
        If `n` is 1, return the next element of data (as an int).
        If `n` is > 1, return the next `n` elements of data (as bytes).

        :param n: How many elements to return (see above)
        :param bool bounds: Perform bounds checking on access if True
        """
        dlen = len(self._data)
        if n and bounds and (self._offset + n) > dlen:
            raise SCIONIndexError("%s: Attempted to access beyond end of raw "
                                  "data (len=%d, offset=%d, request=%d)" %
                                  (self._desc, dlen, self._offset, n))
        if n is None:
            return self._data[self._offset:]
        elif n == 1:
            return self._data[self._offset]
        else:
            return self._data[self._offset:self._offset + n]

    def pop(self, n=None, bounds=True):
        """
        Return next elements from data, and advance the internal offset.

        Arguments have the same meaning as for Raw.get
        """
        ret = self.get(n, bounds)
        dlen = len(self._data)
        if n is None:
            self._offset = dlen
        elif n == 1:
            self._offset += 1
        else:
            self._offset += n
        if self._offset > dlen:
            self._offset = dlen
        return ret

    def offset(self):  # pragma: no cover
        return self._offset

    def __len__(self):
        return max(0, len(self._data) - self._offset)
