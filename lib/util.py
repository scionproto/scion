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
import logging
import os
import sys
import signal
import time
from functools import wraps

# External packages
from external.stacktracer import trace_start

# SCION
from lib.defines import TOPOLOGY_PATH

CERT_DIR = 'certificates'
SIG_KEYS_DIR = 'signature_keys'
ENC_KEYS_DIR = 'encryption_keys'
TRACE_DIR = '../traces'

_SIG_MAP = {
    signal.SIGHUP: "SIGHUP",
    signal.SIGINT: "SIGINT",
    signal.SIGQUIT: "SIGQUIT",
    signal.SIGTERM: "SIGTERM",
    signal.SIGUSR1: "SIGUSR1",
    signal.SIGUSR2: "SIGUSR2"
}


def _get_isd_prefix(isd_dir):
    """


    :param isd_dir:
    :type isd_dir:

    :returns:
    :rtype:
    """
    return os.path.join(isd_dir, 'ISD')


def get_cert_chain_file_path(loc_isd, loc_ad, isd_id, ad_id, version,
                             isd_dir=TOPOLOGY_PATH):
    """
    Return the certificate chain file path.

    :param loc_isd: the caller's ISD identifier.
    :type loc_isd: int
    :param loc_ad: the caller's AD identifier.
    :type loc_ad: int
    :param isd_id: the certificate chain's ISD identifier.
    :type isd_id: int
    :param ad_id: the certificate chain's AD identifier.
    :type ad_id: int
    :param version: the certificate chain's version.
    :type version: int

    :returns: the certificate chain file path.
    :rtype: str
    """
    isd_dir_prefix = _get_isd_prefix(isd_dir)
    return os.path.join(isd_dir_prefix + str(loc_isd), CERT_DIR,
                        'AD{}'.format(loc_ad),
                        'ISD:{}-AD:{}-V:{}.crt'.format(isd_id, ad_id, version))


def get_trc_file_path(loc_isd, loc_ad, isd_id, version,
                      isd_dir=TOPOLOGY_PATH):
    """
    Return the TRC file path.

    :param loc_isd: the caller's ISD identifier.
    :type loc_isd: int
    :param loc_ad: the caller's AD identifier.
    :type loc_ad: int
    :param isd_id: the TRC's ISD identifier.
    :type isd_id: int
    :param version: the TRC's version.
    :type version: int

    :returns: the TRC file path.
    :rtype: str
    """
    isd_dir_prefix = _get_isd_prefix(isd_dir)
    return os.path.join(isd_dir_prefix + str(loc_isd), CERT_DIR,
                        'AD{}'.format(loc_ad),
                        'ISD:{}-V:{}.crt'.format(isd_id, version))


def get_sig_key_file_path(isd_id, ad_id, isd_dir=TOPOLOGY_PATH):
    """
    Return the signing key file path.

    :param isd_id: the signing key ISD identifier.
    :type isd_id: int
    :param ad_id: the signing key AD identifier.
    :type ad_id: int

    :returns: the signing key file path.
    :rtype: str
    """
    isd_dir_prefix = _get_isd_prefix(isd_dir)
    return os.path.join(isd_dir_prefix + str(isd_id), SIG_KEYS_DIR,
                        'ISD:{}-AD:{}.key'.format(isd_id, ad_id))


def get_enc_key_file_path(isd_id, ad_id, isd_dir=TOPOLOGY_PATH):
    """
    Return the encryption key file path.

    :param isd_id: the encryption key ISD identifier.
    :type isd_id: int
    :param ad_id: the encryption key AD identifier.
    :type ad_id: int

    :returns: the encryption key file path.
    :rtype: str
    """
    isd_dir_prefix = _get_isd_prefix(isd_dir)
    return os.path.join(isd_dir_prefix + str(isd_id), ENC_KEYS_DIR,
                        'ISD:{}-AD:{}.key'.format(isd_id, ad_id))


def read_file(file_path):
    """
    Read and return content of a file.

    :param file_path: the path to the file.
    :type file_path: str

    :returns: the file content.
    :rtype: str
    """
    if os.path.exists(file_path):
        with open(file_path, 'r') as file_handler:
            text = file_handler.read()
        return text
    else:
        return ''


def write_file(file_path, text):
    """
    Write some text into a file.

    :param file_path: the path to the file.
    :type file_path: str
    :param text: the file content.
    :type text: str
    """
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    with open(file_path, 'w') as file_handler:
        file_handler.write(text)


def update_dict(dictionary, key, values, elem_num=0):
    """
    Update dictionary. Used for managing a temporary paths' cache.
    """
    if key in dictionary:
        dictionary[key].extend(values)
    else:
        dictionary[key] = values
    dictionary[key] = dictionary[key][-elem_num:]


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
    pass


def _signal_handler(signum, _):
    """
    Basic signal handler function

    :param signum:
    :type signum:
    """
    logging.info("Received %s", _SIG_MAP[signum])
    sys.exit(0)


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
