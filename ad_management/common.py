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
:mod:`common` --- AD management tool common functions
=====================================================
"""
# Stdlib
import os
import xmlrpc.client

# Ports
MONITORING_DAEMON_PORT = 9000
SUPERVISORD_PORT = 9001

# Paths
SCION_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
MONITORING_DAEMON_DIR = os.path.join(SCION_ROOT, 'ad_management')
UPDATE_DIR_PATH = os.path.join(MONITORING_DAEMON_DIR, '.update_files')
UPDATE_SCRIPT_PATH = os.path.join(MONITORING_DAEMON_DIR, 'updater.py')
CERT_DIR_PATH = os.path.join(MONITORING_DAEMON_DIR, 'certs')
SUPERVISORD_PATH = os.path.join(SCION_ROOT, 'supervisor', 'supervisor.sh')
WEB_SCION_DIR = os.path.join(SCION_ROOT, 'web_scion')

# TODO modify after update management is implemented
ARCHIVE_DIST_PATH = os.path.join(SCION_ROOT, 'dist')


# Process names
MONITORING_DAEMON_PROC_NAME = 'monitoring_daemon'


def get_supervisor_server(host='localhost'):
    """


    :param host:
    :type host:
    :returns:
    :rtype:
    """
    url = 'http://{}:{}/RPC2'.format(host, SUPERVISORD_PORT)
    return xmlrpc.client.ServerProxy(url)


def get_monitoring_server(host='localhost'):
    """


    :param host:
    :type host:
    :returns:
    :rtype:
    """
    url = 'https://{}:{}/'.format(host, MONITORING_DAEMON_PORT)
    return xmlrpc.client.ServerProxy(url)


# Response wrappers for monitoring client/server.
# Response is represented as a list, the first element is a boolean value,
# which shows the nature of the response (True -- success, False -- failure).
# The rest of the elements are messages or errors, depending on the response
# type.

def response_success(*data):
    """


    :param data:
    :type data:
    :returns:
    :rtype:
    """
    return [True] + list(data)


def get_data(response):
    """


    :param response:
    :type response:
    :returns:
    :rtype:
    """
    if len(response) >= 2:
        return response[1]
    else:
        return None


def get_success_data(response):
    """


    :param response:
    :type response:
    :returns:
    :rtype:
    """
    return get_data(response)


def response_failure(*errors):
    """


    :param errors:
    :type errors:
    :returns:
    :rtype:
    """
    return [False] + list(errors)


def get_failure_errors(response):
    """


    :param response:
    :type response:
    :returns:
    :rtype:
    """
    return get_data(response)


def is_success(response):
    """


    :param response:
    :type response:
    :returns:
    :rtype:
    """
    assert isinstance(response[0], bool)
    return response[0]
