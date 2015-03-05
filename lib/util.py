#util.py

#Copyright 2014 ETH Zurich

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

"""
:mod:`util` --- SCION utilities
===============================

Various utilities for SCION functionality.
"""

from os.path import sys
import os
import logging


ISD_DIR = '../topology/ISD'
CERT_DIR = '/certificates/'
SIG_KEYS_DIR = '/signature_keys/'
ENC_KEYS_DIR = '/encryption_keys/'


def get_cert_file_path(isd_id, ad_id, cert_isd, cert_ad, cert_version):
    """
    Return the certificate file path.

    :param isd_id: caller's ISD identifier.
    :type isd_id: int
    :param ad_id: caller's AD identifier.
    :type ad_id: int
    :param cert_isd: the certificate ISD identifier.
    :type cert_isd: int
    :param cert_ad: the certificate AD identifier.
    :type cert_ad: int
    :param cert_version: the certificate version.
    :type cert_version: int
    :returns: the certificate file path.
    :rtype: str
    """
    return (ISD_DIR + str(isd_id) + CERT_DIR + 'AD' + str(ad_id) + '/ISD:' +
        str(cert_isd) + '-AD:' + str(cert_ad) + '-V:' + str(cert_version) +
        '.crt')


def get_trc_file_path(isd_id, ad_id, trc_isd, trc_version):
    """
    Return the TRC file path.

    :param isd_id: caller's ISD identifier.
    :type isd_id: int
    :param ad_id: caller's AD identifier.
    :type ad_id: int
    :param trc_isd: the TRC ISD identifier.
    :type trc_isd: int
    :param trc_version: the TRC version.
    :type trc_version: int
    :returns: the TRC file path.
    :rtype: str
    """
    return (ISD_DIR + str(isd_id) + CERT_DIR + 'AD' + str(ad_id) + '/ISD:' +
        str(trc_isd) + '-V:' + str(trc_version) + '.crt')


def get_sig_key_file_path(isd_id, ad_id, version):
    """
    Return the signing key file path.

    :param isd_id: the signing key ISD identifier.
    :type isd_id: int
    :param ad_id: the signing key AD identifier.
    :type ad_id: int
    :param version: the signing key version.
    :type version: int
    :returns: the signing key file path.
    :rtype: str
    """
    return (ISD_DIR + str(isd_id) + SIG_KEYS_DIR + 'ISD:' + str(isd_id) +
        '-AD:' + str(ad_id) + '-V:' + str(version) + '.key')


def get_enc_key_file_path(isd_id, ad_id, version):
    """
    Return the encryption key file path.

    :param isd_id: the encryption key ISD identifier.
    :type isd_id: int
    :param ad_id: the encryption key AD identifier.
    :type ad_id: int
    :param version: the encryption key version.
    :type version: int
    :returns: the encryption key file path.
    :rtype: str
    """
    return (ISD_DIR + str(isd_id) + ENC_KEYS_DIR + 'ISD:' + str(isd_id) +
        '-AD:' + str(ad_id) + '-V:' + str(version) + '.key')


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
                        format='%(asctime)s [%(levelname)s]\t%(message)s')
