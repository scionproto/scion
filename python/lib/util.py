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
import json
import logging
import os
import shutil
import signal
import sys
import time
from binascii import hexlify
from datetime import datetime, timezone
from socket import MSG_DONTWAIT

# External packages
import yaml
from external.stacktracer import trace_start

# SCION
from lib.errors import (
    SCIONIOError,
    SCIONIndexError,
    SCIONJSONError,
    SCIONParseError,
    SCIONTypeError,
    SCIONYAMLError,
)

TRACE_DIR = 'traces'

_SIG_MAP = {
    signal.SIGHUP: "SIGHUP",
    signal.SIGINT: "SIGINT",
    signal.SIGQUIT: "SIGQUIT",
    signal.SIGTERM: "SIGTERM",
    signal.SIGUSR2: "SIGUSR2"
}


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


def copy_file(src, dst):
    dst_dir = os.path.dirname(dst)
    try:
        os.makedirs(dst_dir, exist_ok=True)
    except OSError as e:
        raise SCIONIOError("Error creating dir '%s': %s" %
                           (dst_dir, e.strerror)) from None
    try:
        shutil.copyfile(src, dst)
    except OSError as e:
        raise SCIONIOError("Error copying '%s' to '%s': %s" %
                           (src, dst, e.strerror)) from None


def load_json_file(file_path):
    """
    Read and parse a JSON config file.

    :param str file_path: the path to the file.
    :returns: JSON data
    :rtype: dict
    :raises:
        lib.errors.SCIONIOError: error opening/reading from file.
        lib.errors.SCIONJSONError: error parsing file.
    """
    try:
        with open(file_path) as f:
            return json.load(f)
    except OSError as e:
        raise SCIONIOError("Error opening '%s': %s" %
                           (file_path, e.strerror)) from None
    except (ValueError, KeyError, TypeError) as e:
        raise SCIONJSONError("Error parsing '%s': %s" %
                             (file_path, e)) from None


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
            return yaml.load(f)
    except OSError as e:
        raise SCIONIOError("Error opening '%s': %s" %
                           (file_path, e.strerror)) from None
    except (yaml.scanner.ScannerError) as e:
        raise SCIONYAMLError("Error parsing '%s': %s" %
                             (file_path, e)) from None


def update_dict(dictionary, key, values, elem_num=0):
    """
    Update dictionary. Used for managing a temporary paths' cache.
    """
    if key in dictionary:
        dictionary[key].extend(values)
    else:
        dictionary[key] = values
    dictionary[key] = dictionary[key][-elem_num:]


def calc_padding(length, block_size):
    """
    Calculate how much padding is needed to bring `length` to a multiple of
    `block_size`.

    :param int length: The length of the data that needs padding.
    :param int block_size: The block size.
    """
    if length % block_size:
        return block_size - (length % block_size)
    else:
        return 0


def trace(id_):
    path = os.path.join(TRACE_DIR, "%s.trace.html" % id_)
    trace_start(path)


def sleep_interval(start, interval, desc, quiet=False):
    """
    Sleep until the `interval` seconds have elapsed since `start`.

    If the interval is already over, log a warning with `desc` at the start.

    :param float start:
        Time (in seconds since the Epoch) the current interval started.
    :param float interval: Length (in seconds) of an interval.
    :param str desc: Description of the operation.
    :param bool quiet: If set, don't log warnings.
    """
    now = SCIONTime.get_time()
    delay = start + interval - now
    if delay < 0:
        if not quiet:
            logging.warning(
                "%s took too long: %.3fs (should have been <= %.3fs)",
                desc, now - start, interval)
        delay = 0
    time.sleep(delay)


def handle_signals():
    """Setup basic signal handler for the most common signals."""
    # FIXME(kormat): the SIGUSR1 handler is actually silently overridden by
    # pycapnp, so we can't use/catch it.
    # https://github.com/jparyani/pycapnp/issues/101
    for sig in _SIG_MAP.keys():
        signal.signal(sig, _signal_handler)


def _signal_handler(signum, _):
    """Basic signal handler function."""
    text = "Received %s" % _SIG_MAP[signum]
    if signum == signal.SIGTERM:
        logging.info(text)
        sys.exit(0)
    elif signum == signal.SIGINT:
        logging.info(text)
    else:
        logging.error(text)
    sys.exit(1)


def iso_timestamp(ts):  # pragma: no cover
    """
    Format a unix timestamp as a UTC ISO 8601 format string
    (YYYY-MM-DD HH:MM:SS.mmmmmm+00:00)

    :param float ts: Seconds since the UNIX epoch.
    """
    return str(datetime.fromtimestamp(ts, tz=timezone.utc))


def hex_str(raw):
    """Format a byte string as hex characters."""
    return hexlify(raw).decode("ascii")


def recv_all(sock, total_len, flags):
    barr = bytearray()
    while len(barr) < total_len:
        # The first recv call must support non-blocking mode to raise an error
        # if the socket is not ready. Subsequent calls should be blocking to
        # avoid sync problems.
        if flags & MSG_DONTWAIT and len(barr) > 0:
            flags &= ~MSG_DONTWAIT
        try:
            buf = sock.recv(total_len - len(barr), flags)
        except InterruptedError:
            continue
        except ConnectionResetError:
            # Peer closed the connection without reading
            logging.error("socket closed by peer")
            return None
        if not buf:
            if not barr:
                logging.debug("recv returned nil, socket closed")
            else:
                logging.error("socket connection prematurely terminated")
            return None
        barr += buf
    return bytes(barr)


class SCIONTime(object):
    """A class to return current time."""
    # Function which would return time upon calling it
    #  Can be set using set_time_method
    _custom_time = None

    @classmethod
    def get_time(cls):
        """Get current time."""
        if cls._custom_time:
            return cls._custom_time()
        else:
            return time.time()

    @classmethod
    def set_time_method(cls, method=None):
        """Set the method used to get time."""
        cls._custom_time = method


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
