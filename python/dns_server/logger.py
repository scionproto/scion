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
:mod:`logger` --- Wraps dnslib's DNSLogger
==========================================
"""
# Stdlib
import logging
import time

# External packages
from dnslib import QTYPE, RCODE
from dnslib.server import DNSLogger
from lib.util import hex_str

# SCION
from lib.defines import STARTUP_QUIET_PERIOD


class SCIONDnsLogger(DNSLogger):  # pragma: no cover
    """
    Sub-class to log DNS events instead of just printing them to stdout.

    See `the dns lib source
    <https://bitbucket.org/paulc/dnslib/src/
    68842cf47aca1d283ea4f87bf46d07a3f96e598a/
    dnslib/server.py?at=default#cl-193>`_
    for how to configure what gets logged.
    """

    def __init__(self, *args, level=logging.DEBUG, **kwargs):
        self._startup = time.time()
        self.level = level
        super().__init__(*args, **kwargs)

    def log_prefix(self, handler):
        return ""

    def _common_prefix(self, handler, data):
        return "[%s:%d] (%s)" % (handler.client_address[0],
                                 handler.client_address[1], handler.protocol)

    def _reply_prefix(self, handler, reply, desc):
        return "%s: %s / '%s' (%s) /" % (
            desc, self._common_prefix(handler, reply), reply.q.qname,
            QTYPE[reply.q.qtype])

    def _format_rrs(self, reply):
        return "RRs: %s" % ",".join([QTYPE[a.rtype] for a in reply.rr])

    def log_recv(self, handler, data):
        logging.log(
            self.level, "Received: %s <%d> : %s",
            self._common_prefix(handler, data), len(data), hex_str(data))

    def log_send(self, handler, data):
        logging.log(
            self.level, "Sent: %s <%d> : %s",
            self._common_prefix(handler, data), len(data), hex_str(data))

    def log_request(self, handler, request):
        logging.log(self.level, "Request: %s / '%s' (%s)",
                    self._common_prefix(handler, request), request.q.qname,
                    QTYPE[request.q.qtype])
        self.log_data(request)

    def log_reply(self, handler, reply):
        level = self.level
        output = [self._reply_prefix(handler, reply, "Reply")]
        if reply.header.rcode == RCODE.NOERROR:
            output.append(self._format_rrs(reply))
        else:
            if (time.time() - self._startup) <= STARTUP_QUIET_PERIOD:
                return
            level = logging.WARNING
            output.append(RCODE[reply.header.rcode])
        logging.log(level, " ".join(output))
        self.log_data(reply)

    def log_truncated(self, handler, reply):
        level = self.level
        logging.log(level, "%s %s",
                    self._reply_prefix(handler, reply, "Truncated Reply"),
                    self._format_rrs(reply))
        self.log_data(reply)

    def log_error(self, handler, e):
        logging.log(logging.ERROR, "Invalid Request: %s :: %s",
                    self._common_prefix(handler, e), e)

    def log_data(self, dnsobj):
        for line in dnsobj.toZone("    ").split("\n"):
            logging.log(self.level, line)
