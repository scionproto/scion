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

import logging
import os
import signal
import time
import traceback
from lib.defines import TOPOLOGY_PATH
from external.stacktracer import trace_start

CERT_DIR = 'certificates'
SIG_KEYS_DIR = 'signature_keys'
ENC_KEYS_DIR = 'encryption_keys'
TRACE_DIR = "../traces"


class _StreamErrorHandler(logging.StreamHandler):
    """
    A logging StreamHandler that will exit the application if there's a logging
    exception.

    We don't try to use the normal logging system at this point because we
    don't know if that's working at all. If it is (e.g. when the exception is a
    formatting error), when we re-raise the exception, it'll get handled by the
    normal process.
    """
    def handleError(self, record):
        self.stream.write("Exception in logging module:\n")
        for line in traceback.format_exc().split("\n"):
            self.stream.write(line+"\n")
        self.flush()
        raise


def _get_isd_prefix(isd_dir):
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
    Updates dictionary. Used for managing a temporary paths' cache.
    """
    if key in dictionary:
        dictionary[key].extend(values)
    else:
        dictionary[key] = values
    dictionary[key] = dictionary[key][-elem_num:]


def init_logging(level=logging.DEBUG):
    """
    Configure logging for components (servers, routers, gateways).
    """
    logging.basicConfig(level=level,
                        handlers=[_StreamErrorHandler()],
                        format='%(asctime)s [%(levelname)s]\t%(message)s')

def log_exception(msg, *args, level=logging.CRITICAL, **kwargs):
    """
    Properly format an exception before logging
    """
    logging.log(level, msg, *args, **kwargs)
    for line in traceback.format_exc().split("\n"):
        logging.log(level, line)

def trace():
    path = os.path.join(TRACE_DIR,
                        "%s.trace.html" % os.environ['SUPERVISOR_PROCESS_NAME'])
    trace_start(path)

def timed(limit):
    """
    Decorator to measure to execution time of a function, and log a warning if
    it takes too long. The wrapped function takes an optional `timed_desc`
    string parameter which is printed as part of the warning. If `timed_desc`
    isn't passed in, then the wrapped function's path is printed instead.

    :param float limit: If the wrapped function takes more than `limit`
                        seconds, log a warning.
    """
    def wrap(f):
        def wrapper(*args, timed_desc=None, **kwargs):
            start = time.time()
            ret = f(*args, **kwargs)
            elapsed = time.time() - start
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

    :param float start: Time (in seconds since the Epoch) the current interval
                        started.
    :param float interval: Length (in seconds) of an interval.
    :param string desc: Description of the operation.
    """
    now = time.time()
    delay = start + interval - now
    if delay < 0:
        logging.warning("%s took too long: %.3fs (should have been <= %.3fs)",
                        desc, now - start, interval)
        delay = 0
    time.sleep(delay)
