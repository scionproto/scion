#!/usr/bin/python3
# Copyright (c) 2009 Fabio Domingues - fnds3000 in gmail.com
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

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
:mod:`scion_proxy` --- SCION Simple HTTP(S) Proxy
=================================================

This is a heavily modified version of the MIT Licensed Python Proxy.
The implementation by Fabio Domingues was used as a starting point
to implement the custom SCION HTTP(S) Proxy.

Currently supported HTTP(S) methods:
 - OPTIONS;
 - GET;
 - HEAD;
 - POST;
 - PUT;
 - DELETE;
 - TRACE;
 - CONNECT.

--Usage:

Simple usage of the proxy would be as follows:
1) Start the proxy server from the top level SCION directory:

python/scion_proxy/scion_proxy.py

By default, the proxy will start at port 8080 on the localhost.

2) Set up your browser to point to the proxy. In Firefox v42, it can
be done by going to the configuration:

Preferences -> Advanced -> Network -> Settings -> Manual Proxy Configuration

and setting the following fields:

HTTP Proxy: 127.0.0.1, Port: 8080


--Forwarding (Bridge) Proxy mode usage:

SCION HTTP(S) Proxy can also be used in the forwarding (bridge) mode.
This mode can be used to connect to another SCION proxy. Bridge mode can
be enabled using the -f (or --forward) flag from the command line
as follows:

python/scion_proxy/scion_proxy.py -f
"""

# Stdlib
import argparse
import logging
import os
import socket
import struct
import threading
from http.client import HTTPMessage
from urllib.parse import urlparse, urlunparse

# SCION
from lib.defines import GEN_PATH, SCIOND_API_SOCKDIR
from lib.log import init_logging, log_exception
from lib.packet.host_addr import HostAddrIPv4
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.thread import thread_safety_net
from lib.types import L4Proto
from lib.util import handle_signals, hex_str
from sciond.sciond import SCIONDaemon
from scion_proxy.scion_socket import ScionServerSocket, ScionClientSocket
from scion_proxy.scion_socket import SCION_OPTION_ISD_WLIST
from scion_proxy.socket_kbase import SocketKnowledgeBase


VERSION = '0.1.0'
BUFLEN = 8192
DEFAULT_SERVER_PORT = 8080
LOG_BASE = 'logs/scion_proxy'
CONN_ID_BYTES = 4

KBASE_SECURITY_WARN = (
    'WARNING: the SCION knowledge-base is insecure, as it exposes '
    'browsing information without any protective authentication or '
    'encryption. It should not be used outside of demo purposes.'
)


class ConnectionHandler(object):
    """
    Handler class for the connection to be proxied.
    """
    server_version = "SCION HTTP Proxy/" + VERSION

    def __init__(self, connection, address, conn_id):
        """
        Create a ConnectionHandler class to handle the incoming HTTP(S) request.
        :param connection: Socket belonging to the incoming connection.
        :type connection: socket
        :param address: Address of the connecting party.
        :type address: host, port
        """
        self.conn_id = conn_id
        self.connection = connection
        self.method = self.path = self.protocol = None
        self.headers = HTTPMessage()

        cur_thread = threading.current_thread()
        cur_thread.name = self.conn_id
        try:
            if not self.parse_request():
                # FIXME(kormat): need error reporting
                return
            self.handle_request()
        finally:
            cleanup(self.connection)

    def parse_request(self):
        """
        Extracts the request line of an incoming HTTP(S) request.
        :returns: HTTP(S) Method, Path, HTTP(S) Protocol Version
        :rtype: triple
        """
        data = []
        lf_count = 0
        while lf_count < 2:
            b = self.connection.recv(1)
            if not b:
                logging.info("Client closed the connection.")
                return False
            if b == b"\r":
                # Drop \r's, as recommended by rfc2616 19.3
                continue
            data.append(b)
            if b == b"\n":
                lf_count += 1
            else:
                lf_count = 0
        lines = b"".join(data).decode("ascii").split("\n")
        self.method, self.path, self.protocol = lines.pop(0).split(" ")
        for line in lines:
            if not line:
                break
            self.headers.add_header(*line.split(": ", 1))
        logging.info("Request: %s %s %s", self.method, self.path, self.protocol)
        logging.debug("Request headers:\n%s", self.headers)
        return True

    def handle_request(self):
        if self.method == 'CONNECT':
            self.do_CONNECT()
        elif self.method in ('GET', 'HEAD', 'POST', 'PUT', 'DELETE'):
            self.handle_others()
        else:
            # FIXME(kormat): need error reporting
            logging.warning("Invalid HTTP(S) request")

    def do_CONNECT(self):
        """
        Handles the CONNECT method: Connects to the target address,
        and responds to the client (i.e. browser) with a 200
        Connection established response and starts proxying.
        """
        soc = self._connect_to(self.path)
        if not soc:
            # FIXME(kormat): needs error handling
            return
        reply = "\r\n".join([
            "HTTP/1.1 200 Connection established",
            "Proxy-agent: %s" % self.server_version
        ]) + "\r\n\r\n"
        try:
            self.connection.send(reply.encode("ascii"))
            self._read_write(soc)
        finally:
            cleanup(soc)

    def handle_others(self):
        """
        Handles the rest of the supported HTTP methods: Parses the path,
        connects to the target address, sends the complete request
        to the target and starts proxying.
        """
        (scm, netloc, path, params, query, _) = urlparse(
            self.path, 'http')
        if scm != 'http' or not netloc:
            logging.error("Bad URL %s" % self.path)
            return
        conn_hdr = self.headers["Connection"]
        if conn_hdr:
            del self.headers[conn_hdr]
            self.headers.replace_header("Connection", "close")
        soc = self._connect_to(netloc)
        if not soc:
            # FIXME(kormat): needs error handling
            return
        try:
            # Normal mode proxy strips out scm and netloc
            self._send_request(soc, '', '', path, params, query)
            self._read_write(soc)
        finally:
            cleanup(soc)
        logging.debug("Done")

    def _connect_to(self, netloc):
        """
        Establishes a connection to the target host.
        :param netloc: The hostname (and port) of the target to be connected to.
        :type netloc: string
        :returns: The socket that is used to connect.
        :rtype: socket
        """
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ':' in netloc:
            host, port = netloc.split(':')
        else:
            host, port = netloc, 80
        logging.debug("Connecting to %s:%s" % (host, port))
        try:
            soc.connect((host, int(port)))
        except OSError:
            log_exception("Error while connecting to %s:%s" % (host, port))
            return False
        logging.debug("Connected to %s:%s" % (host, port))
        return soc

    def _send_request(self, soc, scm, netloc, path, params, query):
        """
        Helper function that prepares and sends the request on the
        given socket.
        :param soc: The socket the request is going to be sent on.
        :type soc: socket
        :param path: The path of the HTTP request.
        :type path: String
        :param params: Parameters of the request (if any).
        :type params: String
        :param query: Query section of the HTTP request (if any).
        :type query: String
        """
        base = "%s %s HTTP/1.0" % (
            self.method,
            urlunparse((scm, netloc, path, params, query, '')))
        req = []
        req.append(base)
        for hdr, val in self.headers.items():
            req.append("%s: %s" % (hdr, val))
        req_bytes = ("\r\n".join(req) + "\r\n\r\n").encode("ascii")
        logging.debug("Sending a request: %s", req_bytes)
        # FIXME(kormat): need error handling/reporting
        soc.send(req_bytes)

    def _read_write(self, target_sock):
        """
        The main function responsible for the proxying operation. It creates
        two threads to listen for incoming data on both client (i.e. browser)
        and server sockets and relays them accordingly between each other.
        :param target_sock: The socket belonging to the remote target.
        :type target_sock: socket
        """
        t1 = threading.Thread(
            target=thread_safety_net,
            args=(ProxyData, self.connection, target_sock),
            name="%s-c2s" % self.conn_id)
        t1.start()
        t2 = threading.Thread(
            target=thread_safety_net,
            args=(ProxyData, target_sock, self.connection),
            name="%s-s2c" % self.conn_id)
        t2.start()
        # Wait until both threads finish.
        t1.join()
        t2.join()


class ProxyData(object):
    def __init__(self, rsock, wsock):
        self.rsock = rsock
        self.wsock = wsock
        self._run()

    def _run(self):
        while True:
            data = self._read()
            if not data:
                break
            if not self._write(data):
                break
        try:
            self.wsock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        logging.debug("Done")

    def _read(self):
        try:
            return self.rsock.recv(BUFLEN)
        except OSError as e:
            logging.debug("Rsock closed: %s", e)

    def _write(self, data):
        try:
            self.wsock.sendall(data)
        except OSError as e:
            logging.debug("Wsock closed: %s", e)
            return False
        return True


class ForwardingProxyConnectionHandler(ConnectionHandler):
    """
    Handler class for the SCION forwarding (bridge) proxy.
    """
    server_version = "SCION HTTP Bridge Proxy/" + VERSION

    def __init__(self, connection, address, conn_id,
                 scion_mode, kbase, source_isd_as, target_isd_as,
                 target_addr, target_port):
        """
        Create a ConnectionHandler class to handle the incoming
        HTTP(S) request.
        :param connection: Socket object that belong to the incoming connection
        :type connection: socket
        :param address: Address of the connecting party.
        :type address: host, port
        """
        self.scion_mode = scion_mode
        self.socket_kbase = kbase
        self.target_proxy_addr = target_addr, target_port
        isd_as = ISD_AS(target_isd_as)
        host = HostAddrIPv4(self.target_proxy_addr[0])
        self.scion_target_proxy = SCIONAddr.from_values(isd_as, host)
        self.scion_target_port = self.target_proxy_addr[1]
        self.isd_as = source_isd_as
        super().__init__(connection, address, conn_id)

    def handle_request(self):
        logging.debug("Handle request: %s", self.method)
        if self.method in ('CONNECT', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE'):
            self.relay_all()

    def relay_all(self):
        """
        Relays all the supported HTTP(S) methods: Parses the path,
        connects to the target address, sends the complete request
        to the target SCION proxy and starts proxying.
        """
        (scm, netloc, path, params, query, _) = urlparse(self.path)
        soc = self._connect_to_target_proxy()
        if not soc:
            # FIXME(kormat): needs error handling
            return
        try:
            self._send_request(soc, scm, netloc, path, params, query)
            self._read_write(soc)
        finally:
            if self.scion_mode and (self.socket_kbase is not None):
                self.socket_kbase.remove_socket(soc)
            cleanup(soc)
        logging.debug("Done")

    def _connect_to_target_proxy(self):
        """
        Establishes a connection to the target SCION proxy.
        :returns: The socket that is connected to the target proxy.
        :rtype: socket
        """
        if self.scion_mode:
            logging.info("Opening a SCION-socket")
            sockdir = "/run/shm/sciond/%s.sock" % self.isd_as
            soc = ScionClientSocket(L4Proto.SSP, bytes(sockdir, 'ascii'))
            soc.connect(self.scion_target_proxy, self.scion_target_port)
            if self.socket_kbase:
                self._handle_socket_options(soc)
                self.socket_kbase.add_socket(soc, self.conn_id,
                                             self.method, self.path)
        else:
            soc = self._unix_client_socket()
        return soc

    def _handle_socket_options(self, soc):
        """
        Sets the given socket options if they are provided.
        """
        # ISD whitelist
        isd_list = self.socket_kbase.get_ISD_whitelist()
        l = len(isd_list)
        if l <= 10:
            isds = struct.pack("H" * l, *isd_list)
            err = soc.setopt(SCION_OPTION_ISD_WLIST, 0, isds)
            if err != 0:
                logging.error("Set ISD whitelist on SCION socket failed: %s",
                              os.strerror(err))
        else:
            logging.error("ISD whitelist too long, ignoring: Len=%s, List=%s",
                          l, isds)

    def _unix_client_socket(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.debug("Connecting to %s:%s" % self.target_proxy_addr)
        try:
            soc.connect(self.target_proxy_addr)
        except OSError:
            log_exception("Error while connecting to %s:%s" %
                          self.target_proxy_addr)
            cleanup(soc)
            return None
        logging.debug("Connected to target proxy %s:%s" %
                      self.target_proxy_addr)
        return soc


def cleanup(sock):
    try:
        sock.close()
    except OSError:
        pass


def serve_forever(soc, bridge_mode, scion_mode, kbase, source_isd_as,
                  target_isd_as, target_addr, target_port):
    """
    Serve incoming HTTP requests until a KeyboardInterrupt is received.
    :param soc: Socket object that belongs to the server.
    :type soc: socket
    :param handler: The type of class to be instantiated as the
    connection handler.
    :type handler: ConnectionHandler or ForwardingProxyConnectionHandler
    :param scion_soc: Use SCION multi-path sockets.
    :type scion_soc: boolean
    """
    while True:
        con, addr = soc.accept()
        conn_id = hex_str(os.urandom(CONN_ID_BYTES))
        if bridge_mode:
            params = (ForwardingProxyConnectionHandler, con, addr, conn_id,
                      scion_mode, kbase, source_isd_as, target_isd_as,
                      target_addr, target_port)
        else:
            params = ConnectionHandler, con, addr, conn_id

        threading.Thread(target=thread_safety_net, args=params,
                         daemon=True).start()


def scion_server_socket(server_address, api_addr, isd_as):
    logging.info("Starting SCION test server application.")
    soc = ScionServerSocket(L4Proto.SSP, bytes(api_addr, 'ascii'))
    host = HostAddrIPv4(server_address[0])
    saddr = SCIONAddr.from_values(isd_as, host)
    soc.bind(server_address[1], saddr)
    soc.listen()
    return soc


def unix_server_socket(port):
    soc = socket.socket(socket.AF_INET)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = '', port
    soc.bind(server_address)
    logging.info("Starting server at (%s, %s), use <Ctrl-C> to stop" %
                 server_address)
    soc.listen(0)
    return soc


def start_sciond(host, api_addr, isd_as):
    conf_dir = "%s/ISD%d/AS%d/endhost" % (GEN_PATH, isd_as[0], isd_as[1])
    return SCIONDaemon.start(
        conf_dir, host, api_addr=api_addr, run_local_api=True, port=0)


def main():
    """
    Parse the command-line arguments and start the proxy server.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument("--address",
                        help='IP address of the source SCION Proxy',
                        default='127.0.0.1')
    parser.add_argument("-p", "--port",
                        help='Port number to run SCION Proxy on',
                        type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("-f", "--forward", help='Forwarding proxy mode',
                        action="store_true")
    parser.add_argument("-s", "--scion", help='Use SCION multi-path socket',
                        action="store_true")
    parser.add_argument(
        "--WARNING-insecure-kbase", dest="kbase", action="store_true",
        help='Enable SCION knowledge-base. %s' % KBASE_SECURITY_WARN,
    )
    parser.add_argument("-t", "--topo",
                        help='Topology file SCION knowledge-base should use',
                        default='topology/Wide.topo')
    parser.add_argument("-l", "--loc",
                        help='Locations file SCION knowledge-base should use',
                        default='topology/Wide.locations')
    parser.add_argument("--source_isd_as",
                        help='ISD-AS of the source SCION Proxy',
                        default='1-4')
    parser.add_argument("--target_isd_as",
                        help='ISD-AS of the target SCION Proxy',
                        default='3-3')
    parser.add_argument("--target_address",
                        help='IP address of the target SCION Proxy',
                        default='127.0.0.1')
    parser.add_argument("--target_port",
                        help='Port of the target SCION Proxy',
                        type=int, default=9090)
    args = parser.parse_args()

    if args.forward:
        init_logging(LOG_BASE + "_forward", file_level=logging.DEBUG,
                     console_level=logging.INFO)
        logging.info("Operating in forwarding (bridge) mode.")
        isd_as = ISD_AS(args.source_isd_as)
        host = HostAddrIPv4(args.address)
    else:
        init_logging(LOG_BASE, file_level=logging.DEBUG,
                     console_level=logging.INFO)
        logging.info("Operating in normal proxy mode.")
        isd_as = ISD_AS(args.target_isd_as)
        host = HostAddrIPv4(args.target_address)

    # start sciond
    logging.info("Starting sciond for %s", isd_as)
    api_addr = SCIOND_API_SOCKDIR + "%s-%s.sock" % (isd_as[0], isd_as[1])
    sciond = start_sciond(host, api_addr, isd_as)

    kbase = None
    if args.scion:
        logging.info("SCION-socket mode is on.")
        if args.kbase:
            if args.forward:
                logging.warning(
                    "*** SCION-socket knowledge-base is enabled. %s ***",
                    KBASE_SECURITY_WARN)
                kbase = SocketKnowledgeBase(args.topo, args.loc,
                                            ISD_AS(args.source_isd_as),
                                            ISD_AS(args.target_isd_as))
            else:
                logging.info("SCION-socket knowledge-base is supported "
                             "only in forwarding mode.")

    if args.scion and not args.forward:
        logging.info("Starting the server with SCION multi-path socket.")
        soc = scion_server_socket((args.target_address, args.port), api_addr,
                                  ISD_AS(args.target_isd_as))
    else:
        logging.info("Starting the server with UNIX socket.")
        soc = unix_server_socket(args.port)

    worker = threading.Thread(target=serve_forever,
                              args=(soc, args.forward, args.scion, kbase,
                                    args.source_isd_as, args.target_isd_as,
                                    args.target_address, args.target_port),
                              daemon=True)
    worker.start()
    try:
        worker.join()
    finally:
        # Exit gracefully
        logging.info("Closing the socket.")
        soc.close()
        logging.info("Stopping sciond.")
        sciond.stop()


if __name__ == '__main__':
    main()
