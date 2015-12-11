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

Usage:

Simple usage of the proxy would be as follows:
1) Start the proxy server from the top level SCION directory:

endhost/scion_proxy.py

By default, the proxy will start at port 8080 on the localhost.

2) Set up your browser to point to the proxy. In Firefox v42, it can
be done by going to the configuration:

Preferences -> Advanced -> Network -> Settings -> Manual Proxy Configuration

and setting the following fields:

HTTP Proxy: 127.0.0.1, Port: 8080
"""

# Stdlib
import logging
import select
import socket
from http.server import SimpleHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, urlunparse

# SCION
from lib.log import init_logging, log_exception

VERSION = '0.1.0'
BUFLEN = 8192
SERVER_ADDRESS = ('127.0.0.1', 8080)
SELECT_TIMEOUT = 3  # seconds
LOG_BASE = 'logs/scion_proxy'


class ConnectionHandler(SimpleHTTPRequestHandler):
    """
    Handler class for the connection to be proxied.
    """
    server_version = "SCION HTTP Proxy/" + VERSION

    def do_CONNECT(self):
        """
        Handles the CONNECT method: Connects to the target address,
        and responds to the client (i.e. browser) with a 200
        Connection established response and starts proxying.
        """
        logging.info("%s %s" % (self.requestline, self.client_address))
        soc = self._connect_to(self.path)
        if not soc:
            return
        try:
            reply = self.protocol_version + \
                " 200 Connection established\n" + \
                "Proxy-agent: %s\n\n" % self.version_string()
            self.wfile.write(bytes(reply, 'ascii'))
            self._read_write(soc)
        finally:
            soc.close()

    def handle_others(self):
        """
        Handles the rest of the supported HTTP methods: Parses the path,
        connects to the target address, sends the complete request
        to the target and starts proxying.
        """
        logging.info("%s %s" % (self.requestline, self.client_address))
        (scm, netloc, path, params, query, _) = urlparse(
            self.path, 'http')
        if scm != 'http' or not netloc:
            self.send_error(400, "Bad URL %s" % self.path)
            logging.error("Bad URL %s" % self.path)
            return
        soc = self._connect_to(netloc)
        if not soc:
            return
        try:
            self._send_request(soc, path, params, query)
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
            self.send_error(404, "Error during connect.")
            log_exception("Error while connecting to %s:%s" % (host, port))
            return False
        logging.debug("Connected to %s:%s" % (host, port))
        return soc

    def _send_request(self, soc, path, params, query):
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
        h = []
        h.append("%s %s %s" % (
            self.command,
            urlunparse(('', '', path, params, query, '')),
            self.request_version))
        for key_val in self.headers.items():
            h.append("%s: %s" % key_val)
        header = "%s\n\n" % "\n".join(h)
        content_len = int(self.headers.get('content-length', 0))
        body = self.rfile.read(content_len)
        req_bytes = []
        req_bytes.append(bytes(header, 'ascii'))
        req_bytes.append(body)
        logging.debug("Sending a request: %s", req_bytes)
        soc.send(b''.join(req_bytes))

    def _read_write(self, target_sock, max_idling=60):
        """
        The main loop for the proxying operation. Listens for incoming data
        on both client (i.e. browser) and server sockets and relays them
        accordingly between each other.
        :param target_sock: The socket belonging to the remote target.
        :type target_sock: socket
        :param max_idling: Inactivity timeout (in seconds) on the sockets.
        :type max_idling: int
        """
        max_tries = max_idling / SELECT_TIMEOUT
        socks = [self.connection, target_sock]
        target_sock.setblocking(False)
        self.connection.setblocking(False)
        inactivity_count = 0
        while inactivity_count < max_tries:
            inactivity_count += 1
            (ins, _, err) = select.select(socks, [],
                                          socks, SELECT_TIMEOUT)
            if err:
                logging.error("Error occurred during Select.")
                break
            for incoming in ins:
                inactivity_count = 0
                if not self._proxy(incoming, target_sock):
                    return

    def _proxy(self, incoming, target_sock):
        """
        Helper function to go through the incoming data and proxy
        them between client and target.
        :param incoming: Socket that data arrived at.
        :type incoming: socket.
        :param target_sock: Socket to the remote host.
        :type target_sock: socket.
        :returns: Whether successfully proxied between to sockets.
        :rtype: boolean
        """
        if incoming is target_sock:
            input_ = "remote"
            output = "local"
            out = self.connection
        else:
            input_ = "local"
            output = "remote"
            out = target_sock
        try:
            data = incoming.recv(BUFLEN)
        except OSError as e:
            logging.error("Error occurred during recv from %s socket: %s",
                          input_, e)
            return False
        if not data:
            logging.error("Read 0 bytes from %s socket.", input_)
            return False
        try:
            out.sendall(data)
        except OSError as e:
            logging.error("Error occurred during sendall on %s socket: %s",
                          output, e)
            return False
        return True

    # override the handler methods of the SimpleHTTPRequestHandler class
    do_DELETE = handle_others
    do_GET = handle_others
    do_HEAD = handle_others
    do_POST = handle_others
    do_PUT = handle_others
    do_TRACE = handle_others
    do_OPTIONS = handle_others


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

if __name__ == '__main__':
    init_logging(LOG_BASE, file_level=logging.DEBUG, console_level=logging.INFO)
    httpd = ThreadingHTTPServer(SERVER_ADDRESS, ConnectionHandler)
    logging.info("Starting server at (%s, %s), use <Ctrl-C> to stop" %
                 SERVER_ADDRESS)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Exiting")
