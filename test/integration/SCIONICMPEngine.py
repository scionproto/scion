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
:mod:`SCIONICMPEngine` --- Class for ICMP processing
==================================================

Module docstring here.

.. note::
    Fill in the docstring.

"""

# SCION
from lib.packet.scion_icmp import SCIONICMPPacket, SCIONICMPType


class SCIONICMPEngine(object):
    """
    class for the SCION icmp processing
    :ivar sciond: the SCION Daemon
    :type sciond: :class:`endhost.sciond.SCIONDaemon`
    """
    def __init__(self, sciond):
        """
        Create a new SCIONICMPEngine instance

        :param sciond: a SCION daemon instance the engine adheres to

        """
        self.sciond = sciond

    """
    Handle an incoming ICMP Echo packet
    :param icmp_pkt: incoming scion icmp packet
    """
    def _handle_icmp_echo(self, icmp_pkt):
        assert(icmp_pkt.scion_icmp_hdr.icmp_type == SCIONICMPType.ICMP_ECHO)

        # construct an eacho reply based on the echo msg
        icmp_pkt.scion_hdr.reverse()
        icmp_pkt.scion_icmp_hdr.type = SCIONICMPType.ICMP_ECHOREPLY
        # as an echo, we keep the data
        is_reply = True
        return (icmp_pkt, is_reply)

    """
    Handle an incoming scion icmp packet
    :param pkt: incoming scion icmp packet
    """
    def handle_icmp_pkt(self, pkt):

        # TODO: first, assert the packet is icmp packet;
        # however, we need to define scion header's protocol
        # field
        icmp_pkt = SCIONICMPPacket(pkt)
        funct_map = {SCIONICMPType.ICMP_ECHO:
                     SCIONICMPEngine._handle_icmp_echo}
        type = icmp_pkt.scion_icmp_hdr.icmp_type

        if type in funct_map:
            (resp_pkt, is_reply) = funct_map[type](self,
                                                   icmp_pkt)
        else:
            # for unhandled the packet just drop
            is_reply = False

        # send reply back if needed
        if is_reply:
            self.send_icmp_pkt(resp_pkt)

    """
    Send a scion icmp packet
    :param icmp_pkt: the icmp packet to send
    """
    def send_icmp_pkt(self, icmp_pkt):
        (next_hop, port) = self.sciond.\
            get_first_hop_from_scion_hdr(icmp_pkt.scion_hdr)
        self.sciond.send(icmp_pkt, next_hop, port)
