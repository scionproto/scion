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
:mod:`scion_socket` --- Python wrapper for the SCION Multi-Path Socket
======================================================================
"""

# Stdlib
import copy
import ipaddress
import logging
import os
from ctypes import (byref, CDLL, c_double, c_int, c_short, c_ubyte,
                    c_uint, c_ulong, c_ushort, POINTER, Structure)

# SCION
from lib.packet.scion_addr import ISD_AD

ByteArray16 = c_ubyte * 16
MAX_PATHS = 10


class C_HostAddr(Structure):
    _fields_ = [("addrLen", c_int),
                ("addr", ByteArray16),
                ("port", c_short)]


class C_SCIONAddr(Structure):
    _fields_ = [("isd_ad", c_uint),
                ("host", C_HostAddr)]


class C_SCIONInterface(Structure):
    _fields_ = [("ad", c_uint),
                ("isd", c_ushort),
                ("interface", c_ushort)]


class C_SCIONStats(Structure):
    _fields_ = [("exists", c_int * MAX_PATHS),
                ("receivedPackets", c_int * MAX_PATHS),
                ("sentPackets", c_int * MAX_PATHS),
                ("ackedPackets", c_int * MAX_PATHS),
                ("rtts", c_int * MAX_PATHS),
                ("lossRates", c_double * MAX_PATHS),
                ("ifCounts", c_int * MAX_PATHS),
                ("ifLists", POINTER(C_SCIONInterface) * MAX_PATHS),
                ("highestReceived", c_ulong),
                ("highestAcked", c_ulong)]


class ScionStats(object):
    """
    Python class containing SCION socket traffic data
    """

    def __init__(self, stats):
        """
        Python representation of SCION traffic info struct obtained from
        getStats() call. Allows Python wrapper user to not worry about
        dereferencing pointers or freeing memory.
        :param stats: Struct returned by ScionBaseSocket.getStats()
        :type: C_SCIONStats
        """
        self.exists = list(stats.exists)
        self.received_packets = list(stats.receivedPackets)
        self.sent_packets = list(stats.sentPackets)
        self.acked_packets = list(stats.ackedPackets)
        self.rtts = list(stats.rtts)
        self.loss_rates = list(stats.lossRates)
        self.if_counts = list(stats.ifCounts)
        self.if_lists = []
        for i in range(MAX_PATHS):
            if_list = []
            if self.if_counts[i]:
                for j in range(self.if_counts[i]):
                    if_list.append(copy.deepcopy(stats.ifLists[i][j]))
            self.if_lists.append(if_list)
        self.highest_received = copy.deepcopy(stats.highestReceived)
        self.highest_acked = copy.deepcopy(stats.highestAcked)

    def __str__(self):
        """
        String representation of a ScionStats object.
        :returns: The stats as a string.
        :rtype: str
        """
        result = []
        result.append("Sent Packets: " + str(self.sent_packets))
        result.append("Received Packets: " + str(self.received_packets))
        result.append("Acked Packets: " + str(self.acked_packets))
        result.append("RTTs: " + str(self.rtts))
        result.append("Loss-Rates: " + str(self.loss_rates))
        return "\n".join(result)

    def to_dict(self):
        """
        Represents and returns the stats in the form of a dictionary.
        :returns: The stats as a dictionary object.
        :rtype: dict
        """
        result = {}
        result["sent_packets"] = self.sent_packets
        result["received_packets"] = self.received_packets
        result["acked_packets"] = self.acked_packets
        result["rtts"] = self.rtts
        result["loss_rates"] = self.loss_rates
        return result


SHARED_LIB_LOCATION = os.path.join("endhost", "ssp")
SHARED_LIB_SERVER = "libserver.so"
SHARED_LIB_CLIENT = "libclient.so"


class ScionBaseSocket(object):
    """
    Base class of the SCION Multi-Path Socket Python Wrapper.
    """

    def __init__(self, fd, libsock):
        """
        This class can be used if the fd and libsock are known in
        advance. See accept() in ScionServerSocket for an example
        usage.
        :param fd: Underlying file descriptor of the socket.
        :type fd: int
        :param libsock: The relevant SCION Multi-Path Socket library.
        :type: Dynamically loaded shared library (.so).
        """
        self.fd = fd
        self.libsock = libsock

    def send(self, msg):
        """
        Send data to the socket. Returns the number of bytes sent. Applications
        are responsible for checking that all data has been sent; if only some
        of the data was transmitted, the application needs to attempt delivery
        of the remaining data.
        :param msg: The data to be sent on the socket.
        :type msg: bytes
        :returns: The number of bytes sent.
        :rtype: int
        """
        if self.fd == -1:
            logging.warning("Called send after close")
            return 0
        if msg is None or len(msg) == 0:
            return 0
        return self.libsock.SCIONSend(self.fd, msg, len(msg))

    def sendall(self, msg):
        """
        For the SCION multi-path socket this call means only a wrapper for
        send() as it already implements a sendall() style logic internally.
        :param msg: The data to be sent on the socket.
        :type msg: bytes
        :returns: None to indicate success.
        :rtype: NoneType
        """
        self.send(msg)
        return None

    def recv(self, bufsize):
        """
        Receive data from the socket. The return value is a bytes object
        representing the data received. The maximum amount of data to be
        received at once is specified by bufsize.
        :param bufsize: The maximum amount of data to be received at once.
        :type bufsize: int
        :returns: A bytes object representing the data received.
        :rtype: bytes object
        """
        if self.fd == -1:
            logging.critical("Called recv after close")
            return None
        buf = (c_ubyte * bufsize)()
        num_bytes_rcvd = self.libsock.SCIONRecv(self.fd, byref(buf),
                                                bufsize, None)
        if num_bytes_rcvd < 0:
            logging.error("Error during recv.")
            return None
        elif num_bytes_rcvd == 0:
            logging.warning("Received 0 bytes on fd %d. Is the socket closed?"
                            % self.fd)

        return bytes(buf[:num_bytes_rcvd])

    def fileno(self):
        """
        Returns the underlying socket’s file descriptor. This is useful with
        select.select().
        :returns: The socket's file descriptor.
        :rtype: int
        """
        return self.fd

    def getStats(self):
        """
        Allocates and returns structure containing information about socket
        traffic.
        :returns: Python class containing socket traffic data
        :rtype: ScionStats
        """
        self.libsock.SCIONGetStats.restype = POINTER(C_SCIONStats)
        raw_stats = self.libsock.SCIONGetStats(self.fd)
        if not raw_stats:
            return None
        py_stats = ScionStats(raw_stats.contents)
        self.libsock.SCIONDestroyStats(raw_stats)
        return py_stats

    def shutdown(self, how):
        """
        Closes connection.
        The correct closing sequence is:
            - shutdown()
            - recv() until returns 0
            - close()
        This ensures all data that should have been sent before call
        to shutdown was in fact sent and acknowledged.
        :param how: Not implemented yet, placeholder for compatibility
        :type how: int
        """
        self.libsock.SCIONShutdown(self.fd)

    def close(self):
        """
        Destroys underlying socket object and free associated resources.
        """
        self.libsock.deleteSCIONSocket(self.fd)
        self.fd = -1

    def is_alive(self):
        """
        Returns a boolean whether this socket is still active or not.
        """
        return self.fd != -1


class ScionServerSocket(ScionBaseSocket):
    """
    Server side wrapper of the SCION Multi-Path Socket.
    """

    def __init__(self, proto, server_port, fd=None):
        """
        :param proto: The type of SCION socket protocol to be used
        (see lib/defines).
        :type proto: int
        :param server_port: The port number that the server will listen on.
        :type server_port: int
        """
        self.proto = proto
        self.server_port = server_port
        self.libsock = CDLL(os.path.join(SHARED_LIB_LOCATION,
                                         SHARED_LIB_SERVER))
        if fd is None:
            self.fd = self.libsock.newSCIONSocket(proto, None,
                                                  1, server_port, 0)
        else:
            self.fd = fd

        logging.info("ScionServerSocket fd = %d" % self.fd)

    def accept(self):
        """
        Accepts a connection. The return value is a pair (conn, address) where
        conn is a new ScionBaseSocket object usable to send and receive data on
        the connection, and address is the address bound to the socket on the
        other end of the connection. Currently returning the address is not
        supported (i.e. it will always return None).
        :returns: A new SCION socket object usable to send/receive data on the
        connection.
        :rtype: Address tuple (ScionBaseSocket, Address)
        """
        newfd = self.libsock.SCIONAccept(self.fd)
        logging.info("Accepted socket %d" % newfd)
        return ScionBaseSocket(newfd, self.libsock), None


class ScionClientSocket(ScionBaseSocket):
    """
    Client side wrapper of the SCION Multi-Path Socket.
    """

    def __init__(self, proto, isd_ad, target_address):
        """
        :param proto: The type of SCION socket protocol to be used
        (see lib/defines).
        :type proto: int
        :param isd_ad: ISD and AD tuple
        :type isd_ad: int tuple
        :param target_address: The address of the server to connect to.
        :type target_address: (string, int) tuple
        """
        self.proto = proto
        self.isd, self.ad = isd_ad
        self.target_IP, self.target_port = target_address
        self.libsock = CDLL(os.path.join(SHARED_LIB_LOCATION,
                                         SHARED_LIB_CLIENT))
        sa = C_SCIONAddr()
        sa.isd_ad = c_uint(ISD_AD(self.isd, self.ad).int())
        ip_bytes = ipaddress.ip_interface(self.target_IP).ip.packed
        sa.host.addrLen = len(ip_bytes)
        sa.host.addr = ByteArray16(*ip_bytes)
        self.fd = self.libsock.newSCIONSocket(proto, byref(sa), 1,
                                              0, self.target_port)
        logging.info("ScionClientSocket fd = %d" % self.fd)
