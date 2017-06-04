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
:mod:`servers` --- Wrappers around dnslib's TCPServer and UDPServer
===================================================================
"""
# Stdlib
import threading

# External packages
from dnslib.server import TCPServer, UDPServer

# SCION
from lib.log import log_exception
from lib.thread import kill_self


class SCIONDnsTcpServer(TCPServer):
    """
    Sub-class to provide thread naming and error handling for
    dnslib.server.TCPServer
    """

    def serve_forever(self):
        cur_thread = threading.current_thread()
        cur_thread.name = "DNS service - TCP"
        super().serve_forever()

    def handle_error(self, *args, **kwargs):
        log_exception("Error when serving DNS request:")
        kill_self()


class SCIONDnsUdpServer(UDPServer):
    """
    Sub-class to provide thread naming and error handling for
    dnslib.server.UDPServer
    """

    def serve_forever(self):
        cur_thread = threading.current_thread()
        cur_thread.name = "DNS service - UDP"
        super().serve_forever()

    def handle_error(self, *args, **kwargs):
        log_exception("Error when serving DNS request:")
        kill_self()
