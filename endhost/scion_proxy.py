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
 - GET;
 - HEAD;
 - POST;
 - PUT;
 - DELETE;
 - CONNECT.

--Usage:

Simple usage of the proxy would be as follows:
1) Start the proxy server from the top level SCION directory:

endhost/scion_proxy.py

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

endhost/scion_proxy.py -f
"""

# Stdlib
import argparse
import logging
import socket
import threading
from urllib.parse import urlparse, urlunparse

# SCION
from endhost.scion_socket import ScionServerSocket, ScionClientSocket
from lib.defines import L4_SSP
from lib.log import init_logging, log_exception
from lib.thread import thread_safety_net

VERSION = '0.1.0'
BUFLEN = 8192
DEFAULT_SERVER_IP = '127.0.0.1'
DEFAULT_SERVER_PORT = 8080
LOG_BASE = 'logs/scion_proxy'


class ConnectionHandler(object):
    """
    Handler class for the connection to be proxied.
    """
    server_version = "SCION HTTP Proxy/" + VERSION

    def __init__(self, connection, address):
        """
        Create a ConnectionHandler class to handle the incoming HTTP(S) request.
        :param connection: Socket belonging to the incoming connection.
        :type connection: socket
        :param address: Address of the connecting party.
        :type address: host, port
        """
        self.connection = connection
        self.client_buffer = b''
        self.method, self.path, self.protocol = self.get_base_header()
        if self.method == 'CONNECT':
            self.do_CONNECT()
        elif self.method in ('GET', 'HEAD', 'POST', 'PUT', 'DELETE'):
            self.handle_others()
        else:
            logging.warning("Invalid HTTP(S) header: %s" %
                            self.client_buffer)
        self.connection.close()

    def get_base_header(self):
        """
        Extracts the request line of an incoming HTTP(S) request.
        :returns: HTTP(S) Method, Path, HTTP(S) Protocol Version
        :rtype: triple
        """
        while True:
            received = self.connection.recv(BUFLEN)
            if not received:
                # connection is shut down
                logging.info("Client closed the connection.")
                return 'Unrecognized', 'Unrecognized', 'Unrecognized'
            self.client_buffer += received
            newline_loc = self.client_buffer.find(b'\n')
            if newline_loc != -1:
                end = newline_loc
                break
            carriage_return_loc = self.client_buffer.find(b'\r')
            if carriage_return_loc != -1:
                end = carriage_return_loc
                break
        logging.info("Requestline = %s" % self.client_buffer[:end])
        base_header = self.client_buffer[:end+1].decode('ascii').split()
        self.client_buffer = self.client_buffer[end+1:]
        if not self._remaining_headers_and_strip_keepalive():
            return 'Incomplete', 'Incomplete', 'Incomplete'
        return base_header

    def _remaining_headers_and_strip_keepalive(self):
        """
        Reads the rest of the headers, ensures the request is terminated
        properly and tells the server to close the connection once the request
        is completed.
        :returns: True or False
        :rtype: boolean
        """
        while True:
            end_of_req = self.client_buffer.find(b'\r\n\r\n')
            if end_of_req != -1:
                break
            received = self.connection.recv(BUFLEN)
            if not received:
                # connection is shut down, incomplete (invalid) request
                logging.info("Client closed the connection. Invalid request")
                return False
            self.client_buffer += received
        # explicitly tell the server to close the connection once the request
        # is completed
        self.client_buffer = self.client_buffer.\
            replace(b'Connection: keep-alive',
                    b'Connection: close')
        return True

    def do_CONNECT(self):
        """
        Handles the CONNECT method: Connects to the target address,
        and responds to the client (i.e. browser) with a 200
        Connection established response and starts proxying.
        """
        soc = self._connect_to(self.path)
        if not soc:
            return
        try:
            reply = self.protocol + \
                " 200 Connection established\n" + \
                "Proxy-agent: %s\n\n" % self.server_version
            self.connection.send(bytes(reply, 'ascii'))
            self.client_buffer = b''
            self._read_write(soc)
        finally:
            soc.close()

    def handle_others(self):
        """
        Handles the rest of the supported HTTP methods: Parses the path,
        connects to the target address, sends the complete request
        to the target and starts proxying.
        """
        # Use HTTP 1.0 for all the methods other than CONNECT to make our
        # lives easier (i.e do not allow persistent connections nor the re-use
        # of the same socket for multiple requests).
        self.protocol = 'HTTP/1.0'
        (scm, netloc, path, params, query, _) = urlparse(
            self.path, 'http')
        if scm != 'http' or not netloc:
            logging.error("Bad URL %s" % self.path)
            return
        soc = self._connect_to(netloc)
        if not soc:
            return
        try:
            self._send_request(soc, scm, netloc, path, params, query)
            self._read_write(soc)
        finally:
            soc.close()

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
        base = "%s %s %s\n" % (
            self.method,
            urlunparse((scm, netloc, path, params, query, '')),
            self.protocol)
        req_bytes = []
        req_bytes.append(bytes(base, 'ascii'))
        req_bytes.append(self.client_buffer)
        logging.debug("Sending a request: %s", req_bytes)
        soc.send(b''.join(req_bytes))
        self.client_buffer = b''

    def _read_write(self, target_sock):
        """
        The main function responsible for the proxying operation. It creates
        two threads to listen for incoming data on both client (i.e. browser)
        and server sockets and relays them accordingly between each other.
        :param target_sock: The socket belonging to the remote target.
        :type target_sock: socket
        """
        t1 = threading.Thread(target=thread_safety_net,
                              args=(self._read_write_loop, self.connection,
                                    target_sock))
        t2 = threading.Thread(target=thread_safety_net,
                              args=(self._read_write_loop, target_sock,
                                    self.connection))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def _read_write_loop(self, incoming, target_sock):
        """
        Loop until a maximum number of tries on the sockets and proxy
        the data read between the two sockets. This should normally be
        done with a select.select() call but our SCION multi-path socket
        does not yet support select.
        :param incoming: Socket to read the data from.
        :type incoming: socket.
        :param target_sock: Socket to write the data to.
        :type target_sock: socket.
        """
        while True:
            if not self._proxy(incoming, target_sock):
                break

    def _proxy(self, incoming, target_sock):
        """
        Helper function to go read data from the incoming socket and write
        it out to the target socket.
        :param incoming: Socket to read the data from.
        :type incoming: socket.
        :param target_sock: Socket to write the data to.
        :type target_sock: socket.
        :returns: Whether successfully proxied between to sockets.
        :rtype: boolean
        """
        try:
            data = incoming.recv(BUFLEN)
        except OSError as e:
            logging.error("Error during recv from incoming socket: %s", e)
            return False
        if not data:
            logging.info("Peer closed the connection.")
            try:
                target_sock.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                # we are here most likely because socket was already shut-down.
                # log the exception in any case.
                logging.warning("Caught exception during shutdown: %s", e)
            return False
        try:
            target_sock.sendall(data)
        except OSError as e:
            logging.error("Error during sendall on target socket: %s", e)
            return False
        return True


class ForwardingProxyConnectionHandler(ConnectionHandler):
    """
    Handler class for the SCION forwarding (bridge) proxy.
    """
    server_version = "SCION HTTP Bridge Proxy/" + VERSION
    unix_target_proxy = '127.0.0.1', 9090
    scion_target_proxy = '127.2.26.254', 9090
    isd_ad = 2, 26

    def __init__(self, connection, address, scion_mode):
        """
        Create a ConnectionHandler class to handle the incoming
        HTTP(S) request.
        :param connection: Socket object that belong to the incoming connection
        :type connection: socket
        :param address: Address of the connecting party.
        :type address: host, port
        """
        self.scion_mode = scion_mode
        self.connection = connection
        self.client_buffer = b''
        self.method, self.path, self.protocol = self.get_base_header()
        if self.method in ('CONNECT', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE'):
            self.relay_all()
        else:
            logging.warning("Unrecognized HTTP(S) header: %s" %
                            self.client_buffer)
        self.connection.close()

    def relay_all(self):
        """
        Relays all the supported HTTP(S) methods: Parses the path,
        connects to the target address, sends the complete request
        to the target SCION proxy and starts proxying.
        """
        (scm, netloc, path, params, query, _) = urlparse(self.path)
        soc = self._connect_to_target_proxy()
        if not soc:
            return
        try:
            self._send_request(soc, scm, netloc, path, params, query)
            self._read_write(soc)
        finally:
            soc.close()

    def _connect_to_target_proxy(self):
        """
        Establishes a connection to the target SCION proxy.
        :returns: The socket that is connected to the target proxy.
        :rtype: socket
        """
        if self.scion_mode:
            logging.info("Opening a SCION-socket")
            soc = ScionClientSocket(L4_SSP, self.isd_ad,
                                    self.scion_target_proxy)
        else:
            soc = self._unix_client_socket()
        return soc

    def _unix_client_socket(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.debug("Connecting to %s:%s" % self.unix_target_proxy)
        try:
            soc.connect(self.unix_target_proxy)
        except OSError:
            log_exception("Error while connecting to %s:%s" %
                          self.unix_target_proxy)
            return None
        logging.debug("Connected to target proxy %s:%s" %
                      self.unix_target_proxy)
        return soc


def serve_forever(soc, bridge_mode, scion_mode):
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
        if bridge_mode:
            params = ForwardingProxyConnectionHandler, con, addr, scion_mode
        else:
            params = ConnectionHandler, con, addr

        threading.Thread(target=thread_safety_net,
                         args=params,
                         daemon=True).start()


def scion_server_socket(server_address):
    logging.info("Starting SCION test server application.")
    soc = ScionServerSocket(L4_SSP, server_address[1])
    return soc


def unix_server_socket(server_address):
    soc = socket.socket(socket.AF_INET)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc.bind(server_address)
    logging.info("Starting server at (%s, %s), use <Ctrl-C> to stop" %
                 server_address)
    soc.listen(0)
    return soc


def main():
    """
    Parse the command-line arguments and start the proxy server.
    """
    init_logging(LOG_BASE, file_level=logging.DEBUG,
                 console_level=logging.DEBUG)
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port",
                        help='Port number to run SCION Proxy on',
                        type=int, default=DEFAULT_SERVER_PORT)
    parser.add_argument("-f", "--forward", help='Forwarding proxy mode',
                        action="store_true")
    parser.add_argument("-s", "--scion", help='Use SCION multi-path socket',
                        action="store_true")
    args = parser.parse_args()

    server_address = DEFAULT_SERVER_IP, args.port

    if args.forward:
        logging.info("Operating in Forwarding (Bridge) mode.")

    if args.scion:
        logging.info("SCION-socket mode is on.")

    if args.scion and not args.forward:
        logging.info("Starting the server with SCION multi-path socket.")
        soc = scion_server_socket(server_address)
    else:
        logging.info("Starting the server with UNIX socket.")
        soc = unix_server_socket(server_address)

    try:
        serve_forever(soc, args.forward, args.scion)
    except KeyboardInterrupt:
        logging.info("Exiting")
        soc.close()


if __name__ == '__main__':
    main()
