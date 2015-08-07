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
:mod:`util` --- AD management tool common functions
===================================================
"""

# StdLib
import xmlrpc.client

# SCION
from ad_management.common import SUPERVISORD_PORT, MONITORING_DAEMON_PORT
from ad_management.secure_rpc import ServerProxyTLS


# Response wrappers for monitoring client/server.
# Response is represented as a list, the first element is a boolean value,
# which shows the nature of the response (True -- success, False -- failure).
# The rest of the elements are messages or errors, depending on the response
# type.
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
    #return xmlrpc.client.ServerProxy(url)
    return ServerProxyTLS(url)


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