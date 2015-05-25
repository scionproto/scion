#!/usr/bin/env python3

# Monkey patching standard xmlrpc.server.SimpleXMLRPCServer to run over
# TLS (SSL).
#
# Inspired by http://stackoverflow.com/q/5690733/1181370

import socket
import socketserver
import ssl
import os
import logging
import xmlrpc.client
from xmlrpc.server import (SimpleXMLRPCServer, SimpleXMLRPCDispatcher,
                           SimpleXMLRPCRequestHandler)
from ad_management.common import CERT_DIR_PATH

try:
    import fcntl
except ImportError:
    fcntl = None

class XMLRPCServerTLS(SimpleXMLRPCServer):
    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=False, allow_none=False, encoding=None,
                 bind_and_activate=True):
        """
        Overriding __init__ method of the SimpleXMLRPCServer

        The method is an exact copy, except the TCPServer __init__
        call, which is rewritten using TLS
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
