# Copyright 2016 ETH Zurich
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
:mod:`util` --- OPT Utility
===========================================
"""
from lib.opt.ext.opt import OPTExt
from lib.packet.packet_base import PayloadBase
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader


class OPTCreatePacketParams(object):
    """
    Class to store parameters used in create_scion_udp_packet
    """

    session_id = None  # bytes (16b)
    payload = None  # PayloadBase
    session_key_dst = None  # bytes (16b)
    dst = None  # SCIONAddr
    src = None  # SCIONAddr
    port_dst = None  # int
    port_src = None  # int
    path = None  # PathBase


def get_opt_ext_hdr(pkt):
    """
    Get the OPT-Extension header of a packet.

    :param pkt: packet
    :type pkt: SCIONL4Packet
    :returns: the OPT-Extension header of the packet
    :rtype: OPTExt
    """
    for ext_hdr in pkt.ext_hdrs:
        if ext_hdr.EXT_TYPE == OPTExt.EXT_TYPE:
            assert isinstance(ext_hdr, OPTExt)
            return ext_hdr
    return None


def create_scion_udp_packet(params):
    """
    Create a SCIONL4Packet with otp extension.

    :param params: The parameters
    :type params: OPTCreatePacketParams
    :returns: the created packet
    :rtype: SCIONL4Packet
    """
    assert isinstance(params, OPTCreatePacketParams)
    assert isinstance(params.payload, PayloadBase)
    assert isinstance(params.src, SCIONAddr)
    assert isinstance(params.dst, SCIONAddr)

    opt_ext = OPTExt.from_values(params.session_id)
    opt_ext.set_initial_pvf(params.session_key_dst, params.payload)
    cmn_hdr, addr_hdr = build_base_hdrs(params.src, params.dst)
    udp_hdr = SCIONUDPHeader.from_values(params.src, params.port_src,
                                         params.dst, params.port_dst,
                                         params.payload)
    return SCIONL4Packet.from_values(
        cmn_hdr, addr_hdr, params.path, [opt_ext], udp_hdr, params.payload)


def get_remote_session_key(drkeys):
    """
    Get the remote session key from a DRKey object.

    This key is need to initialize the PVF before sending the packet.

    :param drkeys: the DRkeys
    :type drkeys: DRKeys
    :returns: the remote session key
    :rtype: bytes
    """
    if drkeys.is_source:
        return drkeys.dst_key
    else:
        return drkeys.src_key


def get_local_session_key(drkeys):
    """
    Get the local session key from a DRKey object.

    This key is need to initialize the PVF
    when checking the validity of the packet.

    :param drkeys: the DRkeys
    :type drkeys: DRKeys
    :returns: the local session key
    :rtype: bytes
    """
    if not drkeys.is_source:
        return drkeys.dst_key
    else:
        return drkeys.src_key


def get_intermediate_session_keys(drkeys):
    """
    Get the ordered intermediate session keys.

    The keys in the same order as the ASes travers of a received packet.
    Thus, during verification of a received packet,
    simply iterate through the list.

    :param drkeys: the DRkeys
    :type drkeys: DRKeys
    :returns: the ordered session key
    :rtype: [bytes]
    """
    if drkeys.is_source:
        return drkeys.intermediate_keys[::-1]
    else:
        return drkeys.intermediate_keys


def set_answer_packet(pkt, payload, drkeys):
    """
    Reuse packet and set the payload accordingly.

    :param pkt: the packet
    :type pkt: SCIONL4Packet
    :param payload: the payload
    :type payload: PayloadBase
    :param drkeys: the DRKeys
    :type drkeys: DRKeys
    :returns: the modified packet
    :rtype: SCIONL4Packet
    """
    assert payload is not None

    pkt.reverse()
    pkt.set_payload(payload)
    get_opt_ext_hdr(pkt).set_initial_pvf(
        get_remote_session_key(drkeys), payload)
    assert get_opt_ext_hdr(pkt).pvf is not None
    assert get_opt_ext_hdr(pkt).session_id is not None
    return pkt


class OPTStore(object):
    """
    The OPTStore keeps a fingerprint of the received packets.

    This fingerprint is later used to verify the path of the packets.
    """

    def __init__(self):
        # mapping {session_id -> [(data hash, pvf)]} used to verify
        self._fingerprint_map = dict()

    def insert_packet(self, pkt):
        """
        Insert a packet into the OPTStore.

        Packets without an OPT-Extension header are ignored.

        :param pkt: the packet
        :type pkt: SCIONL4Packet
        """

        assert isinstance(pkt, SCIONL4Packet)

        ext_hdr = get_opt_ext_hdr(pkt)
        if ext_hdr:
            if ext_hdr.session_id in self._fingerprint_map:
                self._fingerprint_map[ext_hdr.session_id].append(
                    (OPTExt.compute_data_hash(pkt.get_payload()), ext_hdr.pvf))
            else:
                self._fingerprint_map[ext_hdr.session_id] = [
                    (OPTExt.compute_data_hash(pkt.get_payload()), ext_hdr.pvf)]

    def pop_session(self, session_id):
        """
        Pop all fingerprints of a specified session.

        :param session_id: Session id (16 B)
        :type session_id: bytes
        :returns: a list of all fingerprints
        :rtype: [(bytes,bytes)]
        """
        return self._fingerprint_map.pop(session_id, None)

    @staticmethod
    def _validate_fingerprint_raw(fingerprint, drkeys):
        """
        Verify a fingerprint using a list of bytes.

        Key at position 0 shall be the local session key.
        Key at position i shall be the i-th AS traversed by the packet.

        :param fingerprint: (DataHash, PVF)-pair
        :type fingerprint: (bytes, bytes)
        :param drkeys: list of DRKeys
        :type drkeys: [bytes]
        :returns: if fingerprint was valid
        :rtype: bool
        """
        pvf = OPTExt.compute_initial_pvf(drkeys[0], fingerprint[0])

        for key in drkeys[1:]:
            assert isinstance(key, bytes) and len(key) == 16
            pvf = OPTExt.compute_intermediate_pvf(key, pvf)

        return pvf == fingerprint[1]

    @staticmethod
    def _validate_fingerprint(fingerprint, drkeys):
        """
        Verify a fingerprint using a DRKeys object

        :param fingerprint: (DataHash, PVF)-pair
        :type fingerprint: (bytes, bytes)
        :param drkeys: the DRKeys
        :type drkeys: DRKeys
        :returns: if fingerprint was valid
        :rtype: bool
        """

        pvf = OPTExt.compute_initial_pvf(get_local_session_key(drkeys),
                                         fingerprint[0])

        for key in get_intermediate_session_keys(drkeys):
            assert isinstance(key, bytes) and len(key) == 16
            pvf = OPTExt.compute_intermediate_pvf(key, pvf)

        return pvf == fingerprint[1]

    def validate_session_raw(self, session_id, drkeys):
        """
        Validate a session using a list of bytes.

        Key at position 0 shall be the local session key.
        Key at position i shall be the i-th AS traversed by the packet.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :param drkeys: list of DRKeys
        :type drkeys: [bytes]
        :returns: if all packets in session were valid
        :rtype bool
        """
        for fingerprint in self._fingerprint_map[session_id]:
            if not self._validate_fingerprint_raw(fingerprint, drkeys):
                return False
        return True

    def validate_session(self, session_id, drkeys):
        """
        Validate a session using a DRKey object.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :param drkeys: the DRKeys
        :type drkeys: DRKeys
        :returns: if all packets in session were valid
        :rtype bool
        """

        for fingerprint in self._fingerprint_map[session_id]:
            if not self._validate_fingerprint(fingerprint, drkeys):
                return False
        return True

    def get_sessions(self):
        """
        Returns all Session IDs which are currently in the map.

        :returns: view of all Session IDs
        :rtype dict_keys
        """
        return self._fingerprint_map.keys()

    def number_of_packets(self, session_id):
        """
        Returns the number of packets associated with a given session.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :returns: the number of packets of a session
        :rtype: int
        """
        return len(self._fingerprint_map[session_id])


class DRKeys(object):
    """
    A holder for DRKeys.

    Source is the initiator of the DRKey exchange.
    To get the right key for verification or header initialization use:
       get_remote_session_key
       get_local_session_key
       get_intermediate_session_keys

    """

    def __init__(self, src_key, intermediate_keys, dst_key, is_source):
        """
        Init a DRKey object.

        :param src_key: The key of the initiator of the DRKey exchange
        :type src_key: bytes
        :param intermediate_keys: the keys of the ASes.
        Starting from the source.
        :type intermediate_keys: [bytes]
        :param dst_key: The key of the non-initiator end-host
        :type dst_key: bytes
        :param is_source: indicate if the holder of this DRKeys object
        is the initiator of the DRKey exchange.
        :type is_source: bool
        """
        self.src_key = src_key
        self.intermediate_keys = intermediate_keys
        self.dst_key = dst_key
        self.is_source = is_source

    def __eq__(self, other):
        return (isinstance(other, DRKeys) and
                self.src_key == other.src_key and
                self.intermediate_keys == other.intermediate_keys and
                self.dst_key == other.dst_key)

    def __str__(self):
        return "[src: %s]\n[int: %s]\n[dst: %s]" % \
               (self.src_key, self.intermediate_keys, self.dst_key)

    @classmethod
    def from_bytes_list(cls, bytes_list, src_key):
        """
        Parse bytes list to DRKeys object.

        This method is used by the sciond and
        thus makes some special assumptions.
           The holder of this DRKeys object is not the source
           The keys are inorder of the ASes traversed
           The last key is the local key and thus the dst_key

        :param bytes_list: a list of keys
        :type bytes_list: [bytes]
        :param src_key: the remote key
        :type src_key: bytes
        :returns: a DRKeys object
        :rtype: DRKeys
        """
        return DRKeys(src_key, bytes_list[0:-1], bytes_list[-1], False)
