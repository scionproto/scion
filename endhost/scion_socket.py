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
import errno
import logging
import struct
from ctypes import (
    addressof,
    byref,
    cdll,
    c_double,
    c_int,
    c_short,
    c_size_t,
    c_ubyte,
    c_uint,
    c_void_p,
    Structure,
)

# SCION
from lib.defines import MAX_HOST_ADDR_LEN
from lib.packet.host_addr import haddr_get_type, haddr_parse
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.types import L4Proto
from lib.util import Raw

HostAddrBytes = c_ubyte * MAX_HOST_ADDR_LEN
MAX_PATHS = 20
MAX_OPTION_LEN = 20
SHARED_LIB_FILE = "libssocket.so"


class C_HostAddr(Structure):
    _fields_ = [("addr_type", c_ubyte),
                ("addr", HostAddrBytes),
                ("port", c_short)]


class C_SCIONAddr(Structure):
    _fields_ = [("isd_as", c_uint),
                ("host", C_HostAddr)]


class SCIONInterface(object):
    """
    Class representing interface info, i.e. ISD_AS + IFID

    :ivar ISD_AS isd_as: ISD-AS identifier
    :ivar int ifid: Interface identifier
    """
    NAME = "SCIONInterface"
    LEN = ISD_AS.LEN + 2

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONInterface

        :param raw: Byte string representing interface info
        :type raw: bytes object
        """
        self.isd_as = None
        self.ifid = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse byte string representation

        :param raw: Byte string representing interface info
        :type raw: bytes object
        """
        data = Raw(raw, self.NAME, self.LEN)
        self.isd_as = ISD_AS(data.pop(ISD_AS.LEN))
        self.ifid = struct.unpack("!H", data.pop())[0]

    def __str__(self):
        """
        String representation of a SCIONInterface object.
        :returns: The interface information as a string.
        :rtype: str
        """
        return "(ISD-AS: %s IFID: %s)" % (self.isd_as, self.ifid)

    def to_dict(self):
        """
        Represents and returns the interface as a dictionary.
        :returns: SCION interface as a dictionary object.
        :rtype: dict
        """
        result = {}
        result["ISD"] = self.isd_as[0]
        result["AS"] = self.isd_as[1]
        result["IFID"] = self.ifid
        return result


class C_SCIONOption(Structure):
    _fields_ = [("type", c_int),
                ("val", c_int),
                ("data", c_ubyte * MAX_OPTION_LEN),
                ("len", c_size_t)]


class ScionStats(object):
    """
    Python class containing SCION socket traffic data.
    This class should ONLY be instantiated by the get_stats call in
    ScionBaseSocket.
    """

    FIXED_DATA_LEN = 28

    def __init__(self, raw=None):
        """
        Python representation of SCION traffic data obtained from
        getStats() call. Allows Python wrapper user to not worry about
        dereferencing pointers or freeing memory.

        :param stats: Struct returned by ScionBaseSocket.get_stats()
        :type: C_SCIONStats
        """
        self.received_packets = []
        self.sent_packets = []
        self.acked_packets = []
        self.rtts = []
        self.loss_rates = []
        self.if_counts = []
        self.if_lists = []
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse serialized stats data

        :param raw: Serialized stats data
        :type raw: bytes object
        """
        data = Raw(raw, "Serialized SCION stats", self.FIXED_DATA_LEN, True)
        while len(data):
            values = data.pop(self.FIXED_DATA_LEN)
            # The stats are native byte order
            rp, sp, ap, rtt, lr, ifc = struct.unpack("IIIIdI", values)
            self.received_packets.append(rp)
            self.sent_packets.append(sp)
            self.acked_packets.append(ap)
            self.rtts.append(rtt)
            self.loss_rates.append(lr)
            self.if_counts.append(ifc)
            if ifc:
                if_list = []
                for j in range(ifc):
                    saddr = SCIONInterface(data.pop(ISD_AS.LEN + 2))
                    if_list.append(saddr)
                self.if_lists.append(if_list)

    def __str__(self):
        """
        String representation of a ScionStats object.
        :returns: The stats as a string.
        :rtype: str
        """
        result = []
        result.append("Sent Packets: %s" % self.sent_packets)
        result.append("Received Packets: %s" % self.received_packets)
        result.append("Acked Packets: %s" % self.acked_packets)
        result.append("RTTs: %s" % self.rtts)
        result.append("Loss-Rates: %s" % self.loss_rates)
        result.append("IF Counts: %s" % self.if_counts)
        result.append("IF Lists: %s" % self._if_lists_to_str())
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
        result["if_counts"] = self.if_counts
        iflists = []
        for if_list in self.if_lists:
            ifs = [iface.to_dict() for iface in if_list]
            iflists.append(ifs)
        result["if_lists"] = iflists
        return result

    def _if_lists_to_str(self):
        """
        Converts self.if_lists into string.
        :returns: self.if_lists as a string
        :rtype: str
        """
        result = []
        for if_list in self.if_lists:
            ifs = [str(iface) for iface in if_list]
            result.append("[ %s ]" % " ".join(ifs))
        return "\n".join(result)


# Slightly more than enough for 20 paths with 20 IFs each
MAX_STATS_BUFFER = 3072
# Socket Option codes
SCION_OPTION_BLOCKING = 0
SCION_OPTION_ISD_WLIST = 1


def addr_py2c(saddr=None, port=None):
    """
    Helper function to convert SCIONAddr to C_SCIONAddr
    :param saddr: SCIONAddr to convert
    :type saddr: SCIONAddr
    :param port: Port number to use for connection
    :type port: int
    :returns: Converted struct
    :rtype: C_SCIONAddr
    """
    sa = C_SCIONAddr()
    if saddr:
        sa.isd_as = c_uint(saddr.isd_as.int())
        ip_bytes = saddr.host.pack()
        sa.host.addr_type = saddr.host.TYPE
        sa.host.addr = HostAddrBytes(*ip_bytes)
    else:
        sa.isd_as = 0
        sa.host_addr_type = 0
        sa.host.addr = HostAddrBytes(0)
    if port:
        sa.host.port = port
    else:
        sa.host.port = 0
    return sa


def addr_c2py(caddr):
    """
    Helper function to convert C_SCIONAddr to SCIONAddr
    :param caddr: C_SCIONAddr to convert
    :type caddr: C_SCIONAddr
    :returns: Converted object
    :rtype: SCIONAddr
    """
    isd_as = ISD_AS(caddr.isd_as.to_bytes(4, 'big'))
    if caddr.host.addr_type == 0:
        return None
    htype = haddr_get_type(caddr.host.addr_type)
    haddr = haddr_parse(caddr.host.addr_type,
                        bytes(caddr.host.addr)[:htype.LEN])
    return SCIONAddr.from_values(isd_as, haddr)


class ScionBaseSocket(object):
    """
    Base class of the SCION Multi-Path Socket Python Wrapper.
    """

    # socket options that require long data arg
    # map option to minimum data length for that option
    LONG_OPTIONS = {SCION_OPTION_ISD_WLIST: 0}

    def __init__(self, proto, sciond_addr, fd=None):
        """
        This class can be used if the fd and libssock are known in
        advance. See accept() in ScionServerSocket for an example
        usage.
        :param proto: Protocol number to use for socket
        :type proto: int
        :param sciond_addr: Path to the sciond socket
        :type sciond_addr: string
        :param fd: Underlying file descriptor of the socket.
        :type fd: int
        """
        self.proto = proto
        self.libssock = cdll.LoadLibrary(SHARED_LIB_FILE)
        self.sciond_addr = sciond_addr
        self.port = 0
        if fd:
            self.fd = fd
        else:
            self.fd = self.libssock.newSCIONSocket(self.proto, sciond_addr)

    def bind(self, port, saddr=None):
        """
        Bind socket to SCION address. Bind to any available address by calling
        without saddr argument.
        :param port: Port number to bind
        :type port: int
        :param saddr: SCION address to bind
        :type saddr: SCIONAddr
        :returns: 0 on success, -1 on failure
        :rtype: int
        """
        sa = addr_py2c(saddr, port)
        ret = self.libssock.SCIONBind(self.fd, sa)
        if self.proto == L4Proto.UDP:
            self.port = self.libssock.SCIONGetPort(self.fd)
        return ret

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
        return self.sendto(msg)

    def sendto(self, msg, dst_port=None):
        """
        Send data to the specified destination. Returns number of bytes sent.
        Applications are responsible for checking that all data has been sent;
        if only some of the data was transmitted, the application needs to
        attempt delivery of the remaining data.
        :param msg: The data to be sent on the socket.
        :type msg: bytes
        :param dst: Packet destination
        :type dst: SCIONAddr
        :param port: Destination port number
        :type port: int
        :returns: The number of bytes sent.
        :rtype: int
        """
        if self.fd == -1:
            logging.warning("Called send after close")
            return 0
        if msg is None or len(msg) == 0:
            return 0
        ptr = None
        if dst_port:
            sa = addr_py2c(*dst_port)
            ptr = byref(sa)
        return self.libssock.SCIONSend(self.fd, msg, len(msg), ptr)

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
        return self.recvfrom(bufsize)[0]

    def recvfrom(self, bufsize):
        """
        Receive data from the socket. The return value is a bytes object
        representing the data received. The maximum amount of data to be
        received at once is specified by bufsize.
        :param bufsize: The maximum amount of data to be received at once.
        :type bufsize: int
        :returns: A tuple containing received data and sender information
        :rtype: (bytes, (SCIONAddr, port))
        """
        if self.fd == -1:
            logging.critical("Called recv after close")
            return None, None
        buf = (c_ubyte * bufsize)()
        ca = C_SCIONAddr()
        num_bytes_rcvd = self.libssock.SCIONRecv(
            self.fd, byref(buf), bufsize, byref(ca))
        if num_bytes_rcvd < 0:
            logging.error("Error during recv.")
            return None, None
        elif num_bytes_rcvd == 0:
            logging.debug("Received 0 bytes on fd %d - remote socket closed",
                          self.fd)
        sa = addr_c2py(ca)
        return bytes(buf[:num_bytes_rcvd]), (sa, ca.host.port)

    def recv_all(self, total):
        """
        Repeatedly call recv until total bytes are read.
        :param total: Total size to read from socket.
        :type total: int
        """
        barr = bytearray()
        while len(barr) < total:
            buf = self.recv(total - len(barr))
            if not buf:
                if len(barr) > 0:
                    logging.error("Connection prematurely terminated")
                else:
                    logging.debug("Connection terminated")
                return None
            barr += buf
        return barr

    def fileno(self):
        """
        Returns the underlying socket’s file descriptor. This is useful with
        select.select().
        :returns: The socket's file descriptor.
        :rtype: int
        """
        return self.fd

    def get_stats(self):
        """
        Allocates and returns structure containing information about socket
        traffic.
        :returns: Python class containing socket traffic data
        :rtype: ScionStats
        """
        self.libssock.SCIONGetStats.restype = c_int
        buf = bytes(MAX_STATS_BUFFER)
        stats_len = self.libssock.SCIONGetStats(self.fd, buf, MAX_STATS_BUFFER)
        if not stats_len:
            return None
        py_stats = ScionStats(buf[:stats_len])
        return py_stats

    def setopt(self, opttype, val, data=None):
        """
        Set socket options (currently only supports toggle blocking mode)
        :param opttype: Option type
        :type opttype: int
        :param val: Option value
        :type val: int
        :param data: Long (> 4 bytes) data for complex options
        :type data: bytes object
        :returns: 0 on success, error code on failure (EPERM, EINVAL)
        :rtype: int
        """
        self.libssock.SCIONSetOption.argtypes = (c_int, c_void_p,)
        opt = C_SCIONOption()
        opt.type = opttype
        if data is not None:
            for i, x in enumerate(data):
                opt.data[i] = x
            opt.len = len(data)
            if (opttype not in self.LONG_OPTIONS or
                    (opt.len != 0 and opt.len < self.LONG_OPTIONS[opttype])):
                return -errno.EINVAL
        else:
            assert opttype not in self.LONG_OPTIONS
            opt.data = 0
            opt.len = 0
            opt.val = val
        return self.libssock.SCIONSetOption(self.fd, addressof(opt))

    def getopt(self, opttype):
        """
        Get socket options (currently only supports blocking mode)
        :param opttype: Option type
        :type opttype: int
        :returns: Current option value
        :rtype: bytes object (length will depend on option type)
        """
        self.libssock.SCIONGetOption.argtypes = (c_int, c_void_p,)
        opt = C_SCIONOption()
        opt.type = opttype
        buf = None
        if opttype in self.LONG_OPTIONS:
            buf = bytes(self.LONG_OPTIONS[opttype])
            opt.data = buf
            opt.len = len(buf)
        self.libssock.SCIONGetOption(self.fd, addressof(opt))
        if opttype in self.LONG_OPTIONS:
            return buf
        else:
            return struct.pack("!I", opt.val)

    def get_local_ia(self):
        """
        Get ISD_AS of local address
        :returns: Local ISD_AS, 0 on failure
        :rtype: int
        """
        return self.libssock.SCIONGetLocalIA(self.fd)

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
        self.libssock.SCIONShutdown(self.fd)

    def close(self):
        """
        Destroys underlying socket object and free associated resources.
        """
        self.libssock.deleteSCIONSocket(self.fd)
        self.fd = -1

    def is_alive(self):
        """
        Returns a boolean whether this socket is still active or not.
        """
        return self.fd != -1

    def settimeout(self, timeout):
        """
        Set timeout for socket operations connect/send/recv
        """
        self.libssock.SCIONSetTimeout(self.fd, c_double(timeout))

    def max_payload_size(self, timeout=0.0):
        """
        Get max payload size that can be used on any path known by socket.
        """
        return self.libssock.SCIONMaxPayloadSize(self.fd, c_double(timeout))


class ScionServerSocket(ScionBaseSocket):
    """
    Server side wrapper of the SCION Multi-Path Socket.
    """

    def listen(self):
        """
        Setup the socket to receive incoming connection requests.
        :returns: 0 on success, -1 on failure
        :rtype: int
        """
        ret = self.libssock.SCIONListen(self.fd)
        self.port = self.libssock.SCIONGetPort(self.fd)
        return ret

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
        newfd = self.libssock.SCIONAccept(self.fd)
        logging.debug("Accepted socket %d" % newfd)
        return ScionBaseSocket(self.proto, self.sciond_addr, newfd), None


class ScionClientSocket(ScionBaseSocket):
    """
    Client side wrapper of the SCION Multi-Path Socket.
    """

    def connect(self, saddr, port):
        """
        Connect to remote server using SCION address and port number.
        :param saddr: SCION address of remote server
        :type saddr: SCIONAddr
        :param port: Port number used by remote server
        :type port: int
        :returns: 0 on success, -1 on failure
        :rtype: int
        """
        sa = addr_py2c(saddr, port)
        ret = self.libssock.SCIONConnect(self.fd, sa)
        self.port = self.libssock.SCIONGetPort(self.fd)
        return ret
