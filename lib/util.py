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
from datetime import datetime, timezone
from functools import wraps

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

CERT_DIR = 'certs'
KEYS_DIR = 'keys'
TRACE_DIR = 'traces'

_SIG_MAP = {
    signal.SIGHUP: "SIGHUP",
    signal.SIGINT: "SIGINT",
    signal.SIGQUIT: "SIGQUIT",
    signal.SIGTERM: "SIGTERM",
    signal.SIGUSR1: "SIGUSR1",
    signal.SIGUSR2: "SIGUSR2"
}


def get_cert_chain_file_path(conf_dir, isd_id, ad_id,
                             version):  # pragma: no cover
    """
    Return the certificate chain file path for a given ISD.
    """
    return os.path.join(conf_dir, CERT_DIR,
                        'ISD%s-AD%s-V%s.crt' % (isd_id, ad_id, version))


def get_trc_file_path(conf_dir, isd_id, version):  # pragma: no cover
    """
    Return the TRC file path for a given ISD.
    """
    return os.path.join(conf_dir, CERT_DIR, 'ISD%s-V%s.trc' % (isd_id, version))


def get_sig_key_file_path(conf_dir):  # pragma: no cover
    """
    Return the signing key file path.
    """
    return os.path.join(conf_dir, KEYS_DIR, "ad-sig.key")


def read_file(file_path):
    """
    Read and return contents of a file.

    :param file_path: the path to the file.
    :type file_path: str

    :returns: the file content.
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

    :param file_path: the path to the file.
    :type file_path: str
    :param text: the file content.
    :type text: str
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

    :param file_path: the path to the file.
    :type file_path: str

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

    :param file_path: the path to the file.
    :type file_path: str

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
    """


    :param id_:
    :type id_:
    """
    path = os.path.join(TRACE_DIR, "%s.trace.html" % id_)
    trace_start(path)


def timed(limit):
    """
    Decorator to measure to execution time of a function, and log a warning if
    it takes too long. The wrapped function takes an optional `timed_desc`
    string parameter which is printed as part of the warning. If `timed_desc`
    isn't passed in, then the wrapped function's path is printed instead.

    :param limit: If the wrapped function takes more than `limit`
                        seconds, log a warning.
    :type limit: float
    """
    def wrap(f):
        @wraps(f)
        def wrapper(*args, timed_desc=None, **kwargs):
            start = SCIONTime.get_time()
            ret = f(*args, **kwargs)
            elapsed = SCIONTime.get_time() - start
            if elapsed > limit:
                if not timed_desc:
                    timed_desc = "Call to %s.%s" % (f.__module__, f.__name__)
                logging.warning("%s took too long: %.3fs", timed_desc, elapsed)
            return ret
        return wrapper
    return wrap


def sleep_interval(start, interval, desc):
    """
    Sleep until the `interval` seconds have elapsed since `start`.

    If the interval is already over, log a warning with `desc` at the start.

    :param start: Time (in seconds since the Epoch) the current interval
                        started.
    :type start: float
    :param interval: Length (in seconds) of an interval.
    :type interval: float
    :param desc: Description of the operation.
    :type desc: string
    """
    now = SCIONTime.get_time()
    delay = start + interval - now
    if delay < 0:
        logging.warning("%s took too long: %.3fs (should have been <= %.3fs)",
                        desc, now - start, interval)
        delay = 0
    time.sleep(delay)


def handle_signals():
    """
    Setup basic signal handler for the most common signals
    """
    for sig in _SIG_MAP.keys():
        signal.signal(sig, _signal_handler)


def _signal_handler(signum, _):
    """
    Basic signal handler function

    :param signum:
    :type signum:
    """
    text = "Received %s" % _SIG_MAP[signum]
    if signum == signal.SIGTERM:
        logging.info(text)
        sys.exit(0)
    else:
        logging.error(text)
        sys.exit(1)


def iso_timestamp(ts):
    """
    Format a unix timestamp as a UTC ISO 8601 format string
    (YYYY-MM-DD HH:MM:SS.mmmmmm+00:00)

    :param float ts: Seconds since the UNIX epoch.
    """
    return str(datetime.fromtimestamp(ts, tz=timezone.utc))


class SCIONTime(object):
    """
    A class to return current time
    """
    # Function which would return time upon calling it
    #  Can be set using set_time_method
    _custom_time = None

    @classmethod
    def get_time(cls):
        """
        Get current time
        """
        if cls._custom_time:
            return cls._custom_time()
        else:
            return time.time()

    @classmethod
    def set_time_method(cls, method=None):
        """
        Set the method used to get time
        """
        cls._custom_time = method


class Raw(object):
    """
    Wrapper class to handle raw bytes.

    Wraps raw bytes for easier use in processing of raw bytes. Intuitively,
    this class is a raw byte string like the `bytes` type, but with several
    additional features. The `Raw` class adds a description attribute that also
    serves as a label for the data bytes. The class also can simulate bytes
    being "consumed" during process using an internal offset pointer that can
    be advanced as the raw data is read.
    """

    def __init__(self, data, desc="", len_=None, min_=False):
        """
        Create a `Raw` instance that wraps a `bytes` instance.

        Args:
            data (`bytes`): the raw data to be wrapped.
            desc (str): a description of what the raw data represents.
            len_ (int): the minimum or exact data length requirement for
                `data`.
            min_ (bool): whether `len_` represents a minimum data length.
        """
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

    def offset(self):
        return self._offset

    def __len__(self):
        return max(0, len(self._data) - self._offset)
