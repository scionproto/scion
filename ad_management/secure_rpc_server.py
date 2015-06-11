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
:mod:`secure_rpc_server` --- SimpleXMLRPCServer to run over TLS (SSL)
=====================================================================

Inspired by http://stackoverflow.com/q/5690733/1181370
"""
# Stdlib
import logging
import os
import socket
import socketserver
import ssl
import xmlrpc.client
from xmlrpc.server import (
    SimpleXMLRPCDispatcher,
    SimpleXMLRPCRequestHandler,
    SimpleXMLRPCServer,
)

# SCION
from ad_management.common import CERT_DIR_PATH


try:
    import fcntl
except ImportError:
    fcntl = None


class XMLRPCServerTLS(socketserver.ThreadingMixIn, SimpleXMLRPCServer):
    """
    XML-RPC server with TLS enabled.

    :ivar logRequests:
    :type logRequests:
    :ivar socket:
    :type socket:
    :ivar address_family:
    :type address_family:
    :ivar socket_type:
    :type socket_type:
    :ivar :
    :type :
    """
    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=False, allow_none=False, encoding=None,
                 bind_and_activate=True):
        """
        Initialize an instance of the class XMLRPCServerTLS.

        :param addr:
        :type addr:
        :param requestHandler:
        :type requestHandler:
        :param logRequests:
        :type logRequests:
        :param allow_none:
        :type allow_none:
        :param encoding:
        :type encoding:
        :param bind_and_activate:
        :type bind_and_activate:
        """
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)

        # Add support for long ints
        xmlrpc.client.Marshaller.dispatch[int] = \
            lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

        socketserver.BaseServer.__init__(self, addr, requestHandler)
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            server_side=True,
            cert_reqs=ssl.CERT_NONE,  # TODO
            certfile=os.path.join(CERT_DIR_PATH, 'cert.pem'),
            keyfile=os.path.join(CERT_DIR_PATH, 'key.pem'),
            ssl_version=ssl.PROTOCOL_TLSv1_2,
        )
        logging.warning('Certificate validation is disabled!')
        if bind_and_activate:
            self.server_bind()
            self.server_activate()

        # [Bug #1222790] If possible, set close-on-exec flag; if a
        # method spawns a subprocess, the subprocess shouldn't have
        # the listening socket open.
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)


if __name__ == "__main__":
    server = XMLRPCServerTLS(("localhost", 8000))
    server.register_function(pow)
    server.register_introspection_functions()
    logging.info("Server started...")
    server.serve_forever()
