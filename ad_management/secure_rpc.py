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
:mod:`secure_rpc` --- RPC client/server with TLS/SSL
=====================================================================
"""
# Stdlib
import logging
import os
import socket
import socketserver
import ssl
from xmlrpc.client import SafeTransport, ServerProxy, Marshaller
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

    Inspired by http://stackoverflow.com/q/5690733/1181370

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
        Marshaller.dispatch[int] = \
            lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

        socketserver.BaseServer.__init__(self, addr, requestHandler)
        # TODO: remove fixed certificates
        # Certificates for the management daemon and the web app are fixed, so
        # every AD uses the same certificate. We should generate SSL
        # certificates along with SCION certificates instead, so every AD will
        # have its own certificate.
        cert_reqs = ssl.CERT_REQUIRED
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            server_side=True,
            cert_reqs=cert_reqs,
            ca_certs=os.path.join(CERT_DIR_PATH, 'ca.pem'),
            certfile=os.path.join(CERT_DIR_PATH, 'ad.pem'),
            keyfile=os.path.join(CERT_DIR_PATH, 'ad.key'),
            ssl_version=ssl.PROTOCOL_TLSv1_2,
        )
        if cert_reqs != ssl.CERT_REQUIRED:
            logging.warning('Client certificate verification is disabled!')
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


class VerifyCertSafeTransport(SafeTransport):
    def __init__(self, cafile, certfile=None, keyfile=None):
        super().__init__()
        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self._ssl_context.load_verify_locations(cafile)
        if certfile:
            self._ssl_context.load_cert_chain(certfile, keyfile)
        self._ssl_context.verify_mode = ssl.CERT_REQUIRED

    def make_connection(self, host):
        s = super().make_connection((host, {'context': self._ssl_context,
                                            'check_hostname': False}))
        return s


class ServerProxyTLS(ServerProxy):
    def __init__(self, *args, **kwargs):
        assert 'transport' not in kwargs, 'Use ServerProxy for custom transport'
        # TODO: remove fixed certificates: see above
        md_ca = os.path.join(CERT_DIR_PATH, 'ca.pem')
        client_certfile = os.path.join(CERT_DIR_PATH, 'webapp.pem')
        client_keyfile = os.path.join(CERT_DIR_PATH, 'webapp.key')
        transport = VerifyCertSafeTransport(cafile=md_ca,
                                            certfile=client_certfile,
                                            keyfile=client_keyfile)
        super().__init__(*args, transport=transport, **kwargs)


if __name__ == "__main__":
    server = XMLRPCServerTLS(("localhost", 8000))
    server.register_function(pow)
    server.register_introspection_functions()
    logging.info("Server started...")
    server.serve_forever()
