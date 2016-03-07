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
:mod:`sciond` --- Reference endhost SCION Daemon
================================================
"""
# Stdlib
import base64
import logging
import struct
import threading
from itertools import product

# SCION
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from nacl.utils import random as random_bytes

from lib.opt.util import (DRKeys, get_local_session_key,
                          get_intermediate_session_keys)
from infrastructure.scion_elem import SCIONElement
from lib.crypto.asymcrypto import (decrypt_session_key, sign, verify,
                                   encrypt_session_key, generate_enc_pub_key)
from lib.crypto.certificate import TRC, CertificateChain, Certificate
from lib.crypto.hash_chain import HashChain
from lib.crypto.symcrypto import compute_session_key
from lib.defines import PATH_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONServiceLookupError
from lib.flagtypes import PathSegFlags as PSF
from lib.log import log_exception
from lib.opt.drkey import (DRKeyRequestKey, DRKeyReplyKey, DRKeyAcknowledgeKeys,
                           DRKeySendKeys, DRKeyConstants, DRKeyReplyCertChain,
                           DRKeyRequestCertChain)
from lib.packet.host_addr import haddr_parse
from lib.packet.path import EmptyPath, PathCombinator
from lib.packet.path_mgmt import PathSegmentReq
from lib.packet.pcb_ext import BeaconExtType
from lib.packet.scion import PacketType as PT
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.path_db import DBResult, PathSegmentDB
from lib.requests import RequestHandler
from lib.sibra.ext.resv import ResvBlockSteady
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    DRKeyType as DRKT,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import SCIONTime, Raw, read_file, get_sig_key_file_path

SCIOND_API_HOST = "127.255.255.254"
SCIOND_API_PORT = 3333

# Constants to help with amp access
PATH_LENGTH = 0
ISD_AS_MAP = 1
HOP = 0
SESSION_KEY = 1


class ApiRequestCodes:
    """
    Codes determining the type of the request received by the SCIONDaemon
    when running the local API.
    """
    PATH_REQUEST = 0
    ADDRESS_REQUEST = 1
    OPT_PATH_REQUEST = 2
    OPT_GET_VERIFY_KEYS = 3
    OPT_SHARE_KEYS = 4
    OPT_REMOVE_SESSION = 5


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """
    # Max time for a path lookup to succeed/fail.
    TIMEOUT = 5
    # Number of tokens the PS checks when receiving a revocation.
    N_TOKENS_CHECK = 20
    # Time a path segment is cached at a host (in seconds).
    SEGMENT_TTL = 300
    MAX_SEG_NO = 5  # TODO: replace by config variable.

    def __init__(self, conf_dir, addr, api_addr, run_local_api=False,
                 port=SCION_UDP_PORT):
        """
        Initialize an instance of the class SCIONDaemon.
        """
        super().__init__("sciond", conf_dir, host_addr=addr, port=port)
        # TODO replace by pathstore instance
        self.up_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                         max_res_no=self.MAX_SEG_NO)
        self.down_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        self.core_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL,
                                           max_res_no=self.MAX_SEG_NO)
        self.requests = RequestHandler.start(
            "SCIONDaemon Requests", self._check_segments, self._fetch_segments,
            self._reply_segments, ttl=self.TIMEOUT, key_map=self._req_key_map,
        )
        self._api_socket = None
        self.daemon_thread = None

        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REPLY: self.handle_path_reply,
                PMT.REVOCATION: self.handle_revocation,
            },
            PayloadClass.DRKEY: {
                DRKT.ACKNOWLEDGE_KEYS: self.handle_drkey_ack,
                DRKT.REPLY_KEY: self.handle_drkey_reply,
                DRKT.SEND_KEYS: self.handle_drkey_send,
                DRKT.REQUEST_CERT_CHAIN: self.handle_drkey_cc_req,
                DRKT.REPLY_CERT_CHAIN: self.handle_drkey_cc_rep,
            }
        }
        if run_local_api:
            api_addr = api_addr or SCIOND_API_HOST
            self._api_sock = UDPSocket(
                bind=(api_addr, SCIOND_API_PORT, "sciond local API"),
                addr_type=AddrType.IPV4)
            self._socks.add(self._api_sock)

        key_pair = PrivateKey.generate()
        self._private_key = key_pair.encode()
        self._public_key = key_pair.public_key.encode()
        self._secret_value = random_bytes(16)

        # Map used to gather DRKeys from the ASes.
        # Entry is popped, when an acknowledgment from dst is received.
        # {session_id: [path_length, {isd_ad: (hop, session_key)}]}
        self._session_drkeys_map = dict()

        # Map to keep track of successful DRKey exchange
        # started by remote end-host.
        # {session_id: DRkeys}
        self._drkeys_remote = dict()

        # Map to keep track of successful DRKey exchange
        # started by this end-host.
        # {session_id: (key_local, [keys_interm], key_remote, remote_received)}
        self._drkeys_local = dict()

        # Map to keep track of CertificateChains of remote end-hosts.
        # {hostaddr: CertificateChain}
        self._drkey_cert_chains = dict()

        # Map to keep track of active OPT sessions.
        # {session_id: (PathBase, SCIONAddr)}
        self._active_opt_paths = dict()

        # RequestHandler used to gather DRKeys from the ASes.
        self._drkey_key_requests = RequestHandler.start(
            "SCIONDaemon DRKey Requests", self._check_drkey_key,
            self._fetch_drkey_key, self._reply_drkey_key, ttl=self.TIMEOUT
        )

        # RequestHandler used to get the CertificateChain from an end-host.
        self._drkey_cert_chain_requests = RequestHandler.start(
            "SCIONDaemon DRKey Requests", self._check_drkey_cc,
            self._fetch_drkey_cc, self._reply_drkey_cc, ttl=self.TIMEOUT
        )

        # RequestHandler used to send the DRKeys to the remote end-host.
        self._drkey_send_requests = RequestHandler.start(
            "SCIONDaemon DRKey Requests", self._check_drkey_send,
            self._fetch_drkey_send, self._reply_drkey_send, ttl=self.TIMEOUT
        )

    @classmethod
    def start(cls, conf_dir, addr, api_addr=None, run_local_api=False,
              port=SCION_UDP_PORT):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(conf_dir, addr)
        paths = sd.get_paths(isd_as)
        """
        sd = cls(conf_dir, addr, api_addr, run_local_api, port)
        sd.daemon_thread = threading.Thread(
            target=thread_safety_net, args=(sd.run,), name="SCIONDaemon.run",
            daemon=True)
        sd.daemon_thread.start()
        return sd

    def stop(self):
        """
        Stop SCIONDaemon thread
        """
        logging.info("Stopping SCIONDaemon")
        super().stop()
        self.daemon_thread.join()

    def handle_request(self, packet, sender, from_local_socket=True):
        # PSz: local_socket may be misleading, especially that we have
        # api_socket which is local (in the localhost sense). What do you think
        # about changing local_socket to as_socket
        """
        Main routine to handle incoming SCION packets.
        """
        if not from_local_socket:  # From localhost (SCIONDaemon API)
            self.api_handle_request(packet, sender)
            return
        super().handle_request(packet, sender, from_local_socket)

    def handle_path_reply(self, pkt):
        """
        Handle path reply from local path server.
        """
        added = set()
        path_reply = pkt.get_payload()
        map_ = {
            PST.UP: self._handle_up_seg,
            PST.DOWN: self._handle_down_seg,
            PST.CORE: self._handle_core_seg,
        }
        for type_, pcbs in path_reply.pcbs.items():
            for pcb in pcbs:
                ret = map_[type_](pcb)
                if not ret:
                    continue
                added.add((ret, pcb.flags))
        logging.debug("Added: %s", added)
        for dst_ia, flags in added:
            self.requests.put(((dst_ia, flags), None))

    def _handle_up_seg(self, pcb):
        first_ia = pcb.get_first_pcbm().isd_as
        last_ia = pcb.get_last_pcbm().isd_as
        if self.addr.isd_as != last_ia:
            return None
        if self.up_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Up segment added: %s", pcb.short_desc())
            return first_ia
        return None

    def _handle_down_seg(self, pcb):
        last_ia = pcb.get_last_pcbm().isd_as
        if self.addr.isd_as == last_ia:
            return None
        if self.down_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Down segment added: %s", pcb.short_desc())
            return last_ia
        return None

    def _handle_core_seg(self, pcb):
        first_ia = pcb.get_first_pcbm().isd_as
        if self.core_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Core segment added: %s", pcb.short_desc())
            return first_ia
        return None

    def api_handle_request(self, packet, sender):
        """
        Handle local API's requests.
        """
        if packet[0] == ApiRequestCodes.PATH_REQUEST:  # path request
            logging.info('API: path request from %s.', sender)
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_path_request, packet, sender),
                name="SCIONDaemon", daemon=True).start()
        elif packet[0] == ApiRequestCodes.ADDRESS_REQUEST:  # address request
            self._api_sock.send(self.addr.pack(), sender)
        elif packet[0] == ApiRequestCodes.OPT_PATH_REQUEST:
            logging.info('API: opt path request from %s.', sender)
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_opt_path_request, packet, sender),
                name="SCIONDaemon", daemon=True).start()
        elif packet[0] == ApiRequestCodes.OPT_GET_VERIFY_KEYS:
            logging.info('API: opt key request from %s.', sender)
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_opt_get_verify_keys, packet, sender),
                name="SCIONDaemon", daemon=True).start()
        elif packet[0] == ApiRequestCodes.OPT_SHARE_KEYS:
            logging.info('API: opt share request from %s.', sender)
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_opt_share_keys, packet, sender),
                name="SCIONDaemon", daemon=True).start()
        elif packet[0] == ApiRequestCodes.OPT_REMOVE_SESSION:
            logging.info('API: opt remove request from %s.', sender)
            self._api_handle_opt_remove_session(packet, sender)
        else:
            logging.warning("API: type %d not supported.", packet[0])

    def _api_handle_path_request(self, packet, sender):
        """
        Path request:
          | \x00 (1B) | ISD (12bits) |  AS (20bits)  |
        Reply:
          |p1_len(1B)|p1((p1_len*8)B)|fh_IP(4B)|fh_port(2B)|mtu(2B)|
           p1_if_count(1B)|p1_if_1(5B)|...|p1_if_n(5B)|
           p2_len(1B)|...
         or b"" when no path found. Only IPv4 supported currently.

        FIXME(kormat): make IP-version independant
        """
        dst_ia = ISD_AS(packet[1:ISD_AS.LEN + 1])
        paths = self.get_paths(dst_ia)
        reply = []
        for path in paths:
            raw_path = path.pack()
            # assumed IPv4 addr
            fwd_if = path.get_fwd_if()
            # Set dummy host addr if path is EmptyPath.
            # TODO(PSz): remove dummy "0.0.0.0" address when API is saner
            haddr = self.ifid2addr.get(fwd_if, haddr_parse("IPV4", "0.0.0.0"))
            path_len = len(raw_path) // 8
            reply.append(struct.pack("!B", path_len) + raw_path +
                         haddr.pack() + struct.pack("!H", SCION_UDP_PORT) +
                         struct.pack("!H", path.mtu) +
                         struct.pack("!B", len(path.interfaces)))
            for interface in path.interfaces:
                isd_as, link = interface
                reply.append(isd_as.pack())
                reply.append(struct.pack("!H", link))
        self._api_sock.send(b"".join(reply), sender)

    def _api_handle_opt_path_request(self, packet, sender):
        """
        Handle opt path request.

        Responds with a path which shall be used to send the packets
        and the remote DRKey.
        Additionally starts the non-blocking DRKey exchange.

        Request:
           | \x02 (1B) | Session ID (16B) | SCIONAddr (rest) |
        Reply:
           |p_len(1B)|p((p_len*8)B)|fh_IP(4B)|fh_port(2B)|mtu(2B)|
           |p_if_count(1B)|p_if_1(5B)|...|p1_if_n(5B)| drkey_dst (16B)

          or

           b"" when no path found. Only IPv4 supported currently.

        :param packet: Request received from user.
        :type packet: bytes
        :param sender: (ip, port) pair of the requester.
        :type (string, int)
        """
        offset = 1
        end = offset + DRKeyConstants.SESSION_ID_BYTE_LENGTH
        session_id = packet[offset: end]
        offset += DRKeyConstants.SESSION_ID_BYTE_LENGTH
        logging.debug("%s\nType: %s", packet[offset:], type(packet[offset:]))
        dst = SCIONAddr(("IPV4", packet[offset:]))

        paths = self.get_paths(dst.isd_as)
        path = self._choose_opt_path(paths)

        if not path:
            self._api_sock.send(b"", sender)
            return

        reply = []
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #  Code from '_api_handle_path_request'. Please sync
        raw_path = path.pack()
        # assumed IPv4 addr
        fwd_if = path.get_fwd_if()
        # Set dummy host addr if path is EmptyPath.
        # TODO(PSz): remove dummy "0.0.0.0" address when API is saner
        haddr = self.ifid2addr.get(fwd_if, haddr_parse("IPV4", "0.0.0.0"))
        path_len = len(raw_path) // 8
        reply.append(struct.pack("!B", path_len) + raw_path +
                     haddr.pack() + struct.pack("!H", SCION_UDP_PORT) +
                     struct.pack("!H", path.mtu) +
                     struct.pack("!B", len(path.interfaces)))
        for interface in path.interfaces:
            isd_as, link = interface
            reply.append(isd_as.pack())
            reply.append(struct.pack("!H", link))
        # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        self.init_drkeys(path, session_id, True)
        reply.append(self._get_remote_drkey(session_id))
        self._active_opt_paths[session_id] = path, dst
        self._api_sock.send(b"".join(reply), sender)

    def _api_handle_opt_get_verify_keys(self, packet, sender):
        """
        Handle opt verifying keys request.

        Responds with the keys in order of the packet verification chain
        of a received packet.
        Thus first the local key, then the first hop etc.
        The response is empty, if not all keys are available yet.
        Make sure to request OPT_SHARE_KEYS first.

        Request:
           | \x03 (1B) | Session ID (16B) |
        Reply:
           | drkey_local (16B) | drkey_1 (16B) | ... | drkey_N (16B) |

         or
           b"" if not all keys are available yet.

        :param packet: Request received from user.
        :type packet: bytes
        :param sender: (ip, port) pair of the requester.
        :type (string, int)
        """

        session_id = packet[1:DRKeyConstants.SESSION_ID_BYTE_LENGTH + 1]

        drkeys = self.get_drkeys(session_id)

        if drkeys.intermediate_keys is None:
            self._api_sock.send(b"", sender)
            return

        reply = ([get_local_session_key(drkeys)] +
                 get_intermediate_session_keys(drkeys))
        self._api_sock.send(b"".join(reply), sender)

    def _api_handle_opt_share_keys(self, packet, sender):
        """
        Handles opt share key request.

        This call is blocking and only responds
        after the key has successfully been shared.

        Request:
           | \x04 (1B) | Session ID (16B)

        Reply:
           b""

        :param packet: Request received from user.
        :type packet: bytes
        :param sender: (ip, port) pair of the requester.
        :type (string, int)
        """
        session_id = packet[1:DRKeyConstants.SESSION_ID_BYTE_LENGTH + 1]
        path, dst = self._active_opt_paths[session_id]
        self.send_drkeys(dst, path, session_id)
        self._api_sock.send(b"", sender)

    def _api_handle_opt_remove_session(self, packet, sender):
        """
        Handle opt remove session request.

        Removes the drkeys and the session from memory.

        Request:
          | \x05 (1B) | Session ID (16B) |
        Reply:
           b"" .

        :param packet: Request received from user.
        :type packet: bytes
        :param sender: (ip, port) pair of the requester.
        :type (string, int)
        """
        session_id = packet[1:DRKeyConstants.SESSION_ID_BYTE_LENGTH + 1]
        self.remove_drkeys(session_id)
        self._active_opt_paths.pop(session_id, None)
        self._api_sock.send(b"", sender)

    def handle_revocation(self, pkt):
        """
        Handle revocation.

        :param rev_info: The RevocationInfo object.
        :type rev_info: :class:`lib.packet.path_mgmt.RevocationInfo`
        """
        rev_info = pkt.get_payload()
        logging.info("Received revocation:\n%s", str(rev_info))
        # Verify revocation.
        #         if not HashChain.verify(rev_info.proof, rev_info.rev_token):
        #             logging.info("Revocation verification failed.")
        #             return
        # Go through all segment databases and remove affected segments.
        deletions = self._remove_revoked_pcbs(self.up_segments,
                                              rev_info.rev_token)
        deletions += self._remove_revoked_pcbs(self.core_segments,
                                               rev_info.rev_token)
        deletions += self._remove_revoked_pcbs(self.down_segments,
                                               rev_info.rev_token)
        logging.info("Removed %d segments due to revocation.", deletions)

    def _remove_revoked_pcbs(self, db, rev_token):
        """
        Removes all segments from 'db' that contain an IF token for which
        rev_token is a preimage (within 20 calls).

        :param db: The PathSegmentDB.
        :type db: :class:`lib.path_db.PathSegmentDB`
        :param rev_token: The revocation token.
        :type rev_token: bytes

        :returns: The number of deletions.
        :rtype: int
        """
        to_remove = []
        for segment in db():
            for iftoken in segment.get_all_iftokens():
                if HashChain.verify(rev_token, iftoken, self.N_TOKENS_CHECK):
                    to_remove.append(segment.get_hops_hash())

        return db.delete_all(to_remove)

    def get_paths(self, dst_ia, flags=0):
        """Return a list of paths."""
        logging.debug("Paths requested for %s", dst_ia)
        if self.addr.isd_as == dst_ia or (
                self.addr.isd_as.any_as() == dst_ia and
                self.topology.is_core_as):
            # Either the destination is the local AS, or the destination is any
            # core AS in this ISD, and the local AS is in the core
            return [EmptyPath()]
        deadline = SCIONTime.get_time() + self.TIMEOUT
        e = threading.Event()
        self.requests.put(((dst_ia, flags), e))
        if not self._wait_for_events([e], deadline):
            logging.error("Query timed out for %s", dst_ia)
            return []
        return self.path_resolution(dst_ia, flags=flags)

    def path_resolution(self, dst_ia, flags=0):
        # dst as == 0 means any core AS in the specified ISD.
        dst_is_core = self._is_core_as(dst_ia) or dst_ia[1] == 0
        sibra = bool(flags & PSF.SIBRA)
        if self.topology.is_core_as:
            if dst_is_core:
                ret = self._resolve_core_core(dst_ia, sibra=sibra)
            else:
                ret = self._resolve_core_not_core(dst_ia, sibra=sibra)
        elif dst_is_core:
            ret = self._resolve_not_core_core(dst_ia, sibra=sibra)
        elif sibra:
            ret = self._resolve_not_core_not_core_sibra(dst_ia)
        else:
            ret = self._resolve_not_core_not_core_scion(dst_ia)
        if not sibra:
            return ret
        # FIXME(kormat): Strip off PCBs, and just return sibra reservation
        # blocks
        return self._sibra_strip_pcbs(self._strip_nones(ret))

    def _resolve_core_core(self, dst_ia, sibra=False):
        """Resolve path from core to core."""
        res = set()
        for cseg in self.core_segments(last_ia=self.addr.isd_as, sibra=sibra,
                                       **dst_ia.params()):
                res.add((None, cseg, None))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_core_not_core(self, dst_ia, sibra=False):
        """Resolve path from core to non-core."""
        res = set()
        # First check whether there is a direct path.
        for dseg in self.down_segments(
                first_ia=self.addr.isd_as, last_ia=dst_ia, sibra=sibra):
                res.add((None, None, dseg))
        # Check core-down combination.
        for dseg in self.down_segments(last_ia=dst_ia, sibra=sibra):
            dseg_ia = dseg.get_first_pcbm().isd_as
            if self.addr.isd_as == dseg_ia:
                pass
            for cseg in self.core_segments(
                    first_ia=dseg_ia, last_ia=self.addr.isd_as, sibra=sibra):
                res.add((None, cseg, dseg))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_core(self, dst_ia, sibra=False):
        """Resolve path from non-core to core."""
        res = set()
        params = dst_ia.params()
        params["sibra"] = sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            for useg in self.up_segments(**params):
                res.add((useg, None, None))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            cseg_ia = cseg.get_last_pcbm().isd_as
            for useg in self.up_segments(first_ia=cseg_ia, sibra=sibra):
                res.add((useg, cseg, None))
        if sibra:
            return res
        return PathCombinator.tuples_to_full_paths(res)

    def _resolve_not_core_not_core_scion(self, dst_ia):
        """Resolve SCION path from non-core to non-core."""
        up_segs = self.up_segments()
        down_segs = self.down_segments(last_ia=dst_ia)
        core_segs = self._calc_core_segs(dst_ia[0], up_segs, down_segs)
        full_paths = PathCombinator.build_shortcut_paths(up_segs, down_segs)
        for up_seg in up_segs:
            for down_seg in down_segs:
                full_paths.extend(PathCombinator.build_core_paths(
                    up_seg, down_seg, core_segs))
        return full_paths

    def _resolve_not_core_not_core_sibra(self, dst_ia):
        """Resolve SIBRA path from non-core to non-core."""
        res = set()
        up_segs = set(self.up_segments(sibra=True))
        down_segs = set(self.down_segments(last_ia=dst_ia, sibra=True))
        for up_seg, down_seg in product(up_segs, down_segs):
            src_core_ia = up_seg.get_first_pcbm().isd_as
            dst_core_ia = down_seg.get_first_pcbm().isd_as
            if src_core_ia == dst_core_ia:
                res.add((up_seg, down_seg))
                continue
            core_seg = self.core_segments(first_ia=src_core_ia,
                                          last_ia=dst_core_ia, sibra=True)
            if core_seg:
                res.add((up_seg, core_seg, down_seg))
        return res

    def _strip_nones(self, set_):
        """Strip None entries from a set of tuples"""
        res = []
        for tup in set_:
            res.append(tuple(filter(None, tup)))
        return res

    def _sibra_strip_pcbs(self, paths):
        ret = []
        for pcbs in paths:
            resvs = []
            for pcb in pcbs:
                resvs.append(self._sibra_strip_pcb(pcb))
            ret.append(resvs)
        return ret

    def _sibra_strip_pcb(self, pcb):
        last_asm = pcb.ases[-1]
        info_ext = last_asm.find_ext(BeaconExtType.SIBRA_SEG_INFO)
        assert info_ext
        resv_info = info_ext.info
        resv = ResvBlockSteady.from_values(resv_info, pcb.get_n_hops())
        asms = reversed(pcb.ases) if resv_info.fwd_dir else pcb.ases
        for asm in asms:
            sof_ext = asm.find_ext(BeaconExtType.SIBRA_SEG_SOF)
            resv.sofs.append(sof_ext.sof)
        assert resv.num_hops == len(resv.sofs)
        return info_ext.id, resv

    def _wait_for_events(self, events, deadline):
        """
        Wait on a set of events, but only until the specified deadline. Returns
        the number of events that happened while waiting.
        """
        count = 0
        for e in events:
            if e.wait(max(0, deadline - SCIONTime.get_time())):
                count += 1
        return count

    def _check_segments(self, key):
        """
        Called by RequestHandler to check if a given path request can be
        fulfilled.
        """
        dst_ia, flags = key
        return self.path_resolution(dst_ia, flags=flags)

    def _fetch_segments(self, key, _):
        """
        Called by RequestHandler to fetch the requested path.
        """
        dst_ia, flags = key
        try:
            ps = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            log_exception("Error querying path service:")
            return
        req = PathSegmentReq.from_values(self.addr.isd_as, dst_ia, flags=flags)
        logging.debug("Sending path request: %s", req.short_desc())
        path_request = self._build_packet(ps, payload=req)
        self.send(path_request, ps)

    def _reply_segments(self, key, e):
        """
        Called by RequestHandler to signal that the request has been fulfilled.
        """
        e.set()

    def _req_key_map(self, key, req_keys):
        """
        Called by RequestHandler to know which requests can be answered by
        `key`.
        """
        ans_ia, ans_flags = key
        ret = []
        for req_ia, req_flags in req_keys:
            if req_flags != ans_flags and (not ans_flags & req_flags):
                # The answer and the request have no flags in common, so skip
                # it.
                continue
            if (req_ia == ans_ia) or (req_ia == ans_ia.any_as()):
                # Covers the case where a request was for ISD-0 (i.e. any path
                # to a core AS in the specified ISD)
                ret.append((req_ia, req_flags))
        return ret

    def _calc_core_segs(self, dst_isd, up_segs, down_segs):
        """
        Calculate all possible core segments joining the provided up and down
        segments. Returns a list of all known segments, and a seperate list of
        the missing AS pairs.
        """
        src_core_ases = set()
        dst_core_ases = set()
        for seg in up_segs:
            src_core_ases.add(seg.get_first_pcbm().isd_as[1])
        for seg in down_segs:
            dst_core_ases.add(seg.get_first_pcbm().isd_as[1])
        # Generate all possible AS pairs
        as_pairs = list(product(src_core_ases, dst_core_ases))
        return self._find_core_segs(self.addr.isd_as[0], dst_isd, as_pairs)

    def _find_core_segs(self, src_isd, dst_isd, as_pairs):
        """
        Given a set of AS pairs across 2 ISDs, return the core segments
        connecting those pairs
        """
        core_segs = []
        for src_core_as, dst_core_as in as_pairs:
            src_ia = ISD_AS.from_values(src_isd, src_core_as)
            dst_ia = ISD_AS.from_values(dst_isd, dst_core_as)
            if src_ia == dst_ia:
                continue
            seg = self.core_segments(first_ia=dst_ia, last_ia=src_ia)
            if seg:
                core_segs.extend(seg)
        return core_segs

    def _check_drkey_key(self, session_id):
        """
        Called by RequestHandler to check if all keys on the path
        of a given session are available.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :returns: if all keys are available.
        :rtype: bool
        """

        if session_id not in self._session_drkeys_map:
            return False

        mapping = self._session_drkeys_map[session_id]
        path_length = mapping[PATH_LENGTH]
        number_available_keys = len([x
                                    for x in mapping[ISD_AS_MAP].values()
                                    if x[SESSION_KEY]])

        return path_length == number_available_keys

    def _fetch_drkey_key(self, session_id, request):
        """
        Called by RequestHandler to fetch the drkeys from the ASes on the path
        for a given session.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :param request: (Path, threading Event)-pair
        :type request: (PathBase, Event)
        """
        path, _ = request

        # dict_tuple = (isd_ad_raw, (hop, session_key))
        mapping = self._session_drkeys_map[session_id]
        for dict_tuple in mapping[ISD_AS_MAP].items():
            # session key has not yet been received
            if not dict_tuple[1][SESSION_KEY]:
                isd_as = ISD_AS(raw=dict_tuple[0])
                req = DRKeyRequestKey.from_values(dict_tuple[1][HOP],
                                                  session_id,
                                                  self.create_fake_cert_chain())
                pkt = self._build_packet(PT.CERT_MGMT, path=path,
                                         dst_ia=isd_as, payload=req)
                self._send_to_next_hop(pkt)

    def _reply_drkey_key(self, session_id, request):
        """
        Called by RequestHandler to signal that the request has been fulfilled.

        Stores a tuple in the _drkeys_local map.
        The corresponding session in the _session_drkeys_map will only be popped
        after successfully sharing the drkeys.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :param request: (Path, threading Event) pair
        :type request: (PathBase, Event)
        """
        drkeys = self._get_keys_from_map(session_id)
        if not drkeys:
            return
        remote_key = self._get_remote_drkey(session_id)
        self._drkeys_local[session_id] = (None, drkeys, remote_key, False)
        request[1].set()

    def _start_drkey_exchange(self, path, session_id):
        """
        Starts the session key exchange between the source and the destination.

        The returned threading event is set when all DRKeys are available.

        :param path: chosen path to the address. Make sure path.interfaces
        is defined and not empty.
        :type path: PathBase
        :param session_id: session id (16 B)
        :type session_id: bytes
        :returns: an event, which is set when all intermediate DRKeys
        are available.
        None if DRKeys are already available.
        :rtype: Event
        """
        assert path.interfaces

        if self.get_drkeys(session_id).src_key:
            return None

        if session_id not in self._session_drkeys_map:
            ases = []

            # get all involved ASes
            for e in [inf[0] for inf in path.interfaces]:
                # only care about one hop in the AS
                if e in ases:
                    continue
                ases.append(e)

            assert ases

            map = self._session_drkeys_map
            map[session_id] = (len(ases), dict())
            for hop, isd_as in enumerate(ases):
                map[session_id][ISD_AS_MAP][isd_as.pack()] = (hop, None)

        e = threading.Event()
        self._drkey_key_requests.put((session_id, (path, e)))
        return e

    def _check_drkey_cc(self, host):
        """
        Called by RequestHandler to check if CertificateChain
        of host is available.

        :param host: host address
        :type host: str
        :returns: if a CertificateChain is available
        :rtype: bool
        """
        return host in self._drkey_cert_chains

    def _fetch_drkey_cc(self, host, req):
        """
        Called by RequestHandler to fetch the CertificateChain.

        :param host: host address
        :type host: str
        :param req: (destination address, path, threading event)-tuple
        :type req: (SCIONAddr, PathBase, Event)
        """
        dst, path, _ = req
        snd = DRKeyRequestCertChain.from_values()
        pkt = self._build_packet(dst.host, path=path, dst_ia=dst.isd_as,
                                 payload=snd, dst_port=SCION_UDP_PORT)
        self.send(pkt, host)

    def _reply_drkey_cc(self, _, req):
        """
        Called by RequestHandler to signal that the CertificateChain
        has successfully been received.

        :param req: (destination address, path, threading event)-tuple
        :type req: (SCIONAddr, PathBase, Event)
        """
        req[2].set()

    def _start_cert_chain_requests(self, dst, path):
        """
        Start fetching the CertificateChain from the dst.

        The returned threading event is set when the CertificateChain
        is available.

        :param dst: destination address
        :type dst: SCIONAddr
        :param path: path to destination.
        :type path: PathBase
        :returns: an event, which is set when the CertificateChain is available
        :rtype: Event
        """
        e = threading.Event()
        self._drkey_cert_chain_requests.put((str(dst.host), (dst, path, e)))
        return e

    def _check_drkey_send(self, session_id):
        """
        Called by RequestHandler to check if drkeys
        have been successfully shared.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :returns: if the DRKeys have been successfully shared yet
        :rtype: bool
        """
        return session_id in self._drkeys_local \
            and self._drkeys_local[session_id][3]

    def _fetch_drkey_send(self, session_id, req):
        """
        Called by RequestHandler to share the DRKeys.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :param req: (destination address, path, DRKeys, threading event) tuple
        :type req: (SCIONAddr, PathBase, DRKeys, Event)
        """
        dst, path, keys, _ = req
        cert_local = self.create_fake_cert_chain()
        try:
            cert_remote = self._drkey_cert_chains[str(dst.host)].certs[0]
        except KeyError:
            logging.info("No certificate chain for host: %s", dst.host)
            return

        assert isinstance(cert_remote, Certificate)

        key_list = keys.intermediate_keys + [keys.dst_key]
        cipher = encrypt_session_key(self._private_key,
                                     cert_remote.subject_enc_key,
                                     b"".join(key_list))
        signature = sign(b"".join([cipher, session_id]), self._private_key)
        snd = DRKeySendKeys.from_values(session_id, cipher,
                                        signature, cert_local)
        pkt = self._build_packet(dst.host, path=path, dst_ia=dst.isd_as,
                                 payload=snd, dst_port=SCION_UDP_PORT)
        self.send(pkt, dst.host)

    def _reply_drkey_send(self, _, req):
        """
        Called by RequestHandler to signal that the DRKeys
        have been successfully shared.

        :param req: (destination address, path, DRKeys, threading event) tuple
        :type req: (SCIONAddr, PathBase, DRKeys, Event)
        """
        req[3].set()

    def _start_sending_drkeys(self, dst, path, session_id, keys):
        """
        Start sending the DRKeys to the destination.

        The returned threading event is set when the DRKeys
        have been successfully shared.
        More specific, when a valid DRKeyAcknowledgeKeys packet
        has been received.

        :param dst: destination address
        :type dst: SCIONAddr
        :param path: path to destination.
        :type path: PathBase
        :param session_id: session id of the flow (16 B)
        :type session_id: bytes
        :returns: an event, set when the keys have been successfully shared
        :rtype: Event
        """
        e = threading.Event()
        assert keys.intermediate_keys is not None
        assert keys.dst_key
        self._drkey_send_requests.put((session_id, (dst, path, keys, e)))
        return e

    def _get_remote_drkey(self, session_id):
        """
        Computes session key for the remote host.

        :param session_id: session id (16 B)
        :type session_id: bytes
        :return: bytes (16 B)
        """
        return compute_session_key(self._secret_value, session_id)

    def init_drkeys(self, path, session_id, non_blocking=False):
        """
        Starts the drkey exchange with the ASes on the path.

        In blocking mode (default), this call blocks until all intermediate
        DRKeys have been received.
        The non-blocking call does not guarantee to succeed.

        The path specified has to be the same as the one used for later traffic.
        If the destination is not in the same AS,
        path.interfaces must be non empty.
        If the destination is in the same AS, the Path must be an EmptyPath.
        In that case, the intermediate keys will be an empty list.

        :param path: path to the destination.
           Make sure either path.interfaces is defined or path is EmptyPath
        :type path: PathBase
        :param session_id: session id (16 B)
        :type session_id: bytes
        :param non_blocking: function call non-blocking (default: False)
        :type non_blocking: bool
        """
        assert (path.interfaces or isinstance(path, EmptyPath))

        if isinstance(path, EmptyPath):
            self._drkeys_local[session_id] = \
                (None, [], self._get_remote_drkey(session_id), False)
            return

        e = self._start_drkey_exchange(path, session_id)

        if non_blocking or e is None:  # e is None if keys are already available
            return

        deadline = SCIONTime.get_time() + self.TIMEOUT
        while not self._wait_for_events([e], deadline):
            logging.error("get_drkeys timed out for %s: retry", session_id)
            e = self._start_drkey_exchange(path, session_id)
            deadline = SCIONTime.get_time() + self.TIMEOUT

    def get_drkeys(self, session_id):
        """
        Get a DRKey object for a given session.

        This method returns both drkeys which were initialized locally or
        remotely.
        The origin of the keys is marked in the is_source field.
        If the drkeys are not yet are available, a DRKeys object with dst_key
        and is_source is set.
        However, the intermediate_keys field is None in that case.
        This allows the caller to get the keys needed the set the initial field
        in PVF in OPT and
        start sending the packets right away.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :returns: the DRKeys. DRKey.intermediates is None,
           if keys have not yet been received.
           DRKey.intermediates is [] if dst is in the same AS as src.
        """
        if session_id in self._drkeys_remote:
            return self._drkeys_remote[session_id]
        if session_id in self._drkeys_local:
            key_tuple = self._drkeys_local[session_id]
            return DRKeys(key_tuple[0], key_tuple[1], key_tuple[2], True)
        return DRKeys(None, None, self._get_remote_drkey(session_id), True)

    def _get_keys_from_map(self, session_id):
        """
        Return keys from _session_drkeys_map for given Session ID.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        :returns: list of DRKeys.
        :rtype: [bytes]
        """
        if session_id in self._session_drkeys_map:
            try:
                return [x[1] for
                        x in sorted(
                        self._session_drkeys_map[session_id][1].values(),
                        key=lambda x: x[0])
                        ]
            except KeyError:
                return None

    def request_certificate_chain(self, dst, path, non_blocking=False):
        """
        Request CertificateChain from destination.

        This call can be blocking or non-blocking.
        The non-blocking call does not guarantee, that a certificate
        is received.

        :param dst: destination address
        :type dst: SCIONAddr
        :param path: path to the destination
        :type path: PathBase
        :param non_blocking: function call non-blocking (default: False)
        :type non_blocking: bool
        """
        e = self._start_cert_chain_requests(dst, path)

        if non_blocking:
            return

        deadline = SCIONTime.get_time() + self.TIMEOUT
        while not self._wait_for_events([e], deadline):
            logging.error("request cert chain timed out %s: retry", dst.host)
            e = self._start_cert_chain_requests(dst, path)
            deadline = SCIONTime.get_time() + self.TIMEOUT

    def send_drkeys(self, dst, path, session_id, non_blocking=False):
        """
        Send the drkeys associated with the session to the destination
        using the path.

        If blocking (default) this call waits until the destination acknowledges
        the drkeys and has sent the src_key.
        The non-blocking call is not guaranteed to succeed.

        :param dst: address of the destination
        :type dst: SCIONAddr
        :param path: path to the destination. Make sure either path.interfaces
           is defined or path is EmptyPath.
        :type path: PathBase
        :param session_id: session id (16 B)
        :type session_id: bytes
        :param non_blocking: function call non-blocking (default: False)
        :type non_blocking: bool
        """
        #  handle non blocking case
        if non_blocking:
            drkeys = self.get_drkeys(session_id)
            assert isinstance(drkeys, DRKeys)
            if drkeys.intermediate_keys is None:
                return False
            if dst.host not in self._drkey_cert_chains:
                self._start_cert_chain_requests(dst, path)
                return False
            self._start_sending_drkeys(dst, path, session_id, drkeys)
            return True

        # handle blocking case
        drkeys = self.get_drkeys(session_id)
        if drkeys.intermediate_keys is None:
            logging.info("keys not initialized, waiting... ")
            self.init_drkeys(path, session_id)
            drkeys = self.get_drkeys(session_id)

        self.request_certificate_chain(dst, path)

        e = self._start_sending_drkeys(dst, path, session_id, drkeys)
        deadline = SCIONTime.get_time() + self.TIMEOUT
        while not self._wait_for_events([e], deadline):
            logging.error("send_drkeys timed out for %s: retry", session_id)
            e = self._start_sending_drkeys(dst, path, session_id, drkeys)
            deadline = SCIONTime.get_time() + self.TIMEOUT

        return True

    def remove_drkeys(self, session_id):
        """
        Remove DRKeys associated with Session ID from memory.

        :param session_id: Session ID (16 B)
        :type session_id: bytes
        """
        self._session_drkeys_map.pop(session_id, None)
        self._drkeys_remote.pop(session_id, None)
        self._drkeys_local.pop(session_id, None)

    def handle_drkey_reply(self, pkt):
        """
        Handle a packet containing DRKeyReplyKey as payload.

        Adds the received key to the _session_drkeys_map
        if it is validly signed.

        :param pkt: packet containing the reply
        :type pkt: SCIONL4Packet
        """
        payload = pkt.get_payload()
        assert isinstance(payload, DRKeyReplyKey)

        if payload.session_id not in self._session_drkeys_map:
            logging.info("DRKey replay received for non-valid session %s",
                         payload.session_id)
            return

        isd_as = pkt.addrs.src.isd_as

        # An AS only sends its certificate, if it is not a core AS.
        # All the TRCs of the Core ASes are present anyway.

        # Normal AS -> attached cc
        if payload.certificate_chain:
            assert isinstance(payload.certificate_chain, CertificateChain)
            certificate = payload.certificate_chain.certs[0]
            trc = self.trust_store.get_trc(isd_as[0], certificate.version)
            if not payload.certificate_chain.verify(str(isd_as), trc,
                                                    certificate.version):
                logging.info("DRKey with invalid certificate chain from %s."
                             "\nCertificate Chain:%s\nTRC version:%s",
                             pkt.addrs.src, payload.certificate_chain,
                             certificate.version)
                return
        # Core AS -> TRC present in trust store
        else:
            core_ases = self.trust_store.get_trc(isd_as[0]).core_ases
            if str(isd_as) in core_ases:
                certificate = core_ases[str(isd_as)]
            else:
                logging.info("DRKey Reply no valid certificate "
                             "received from %s", pkt.addrs.src)
                return

        # verify message
        msg = b"".join([payload.cipher, payload.session_id])
        if not verify(msg, payload.signature, certificate.subject_sig_key):
            logging.info("DRKey Reply message not authentic from %s",
                         pkt.addrs.src)
            return

        session_key = decrypt_session_key(self._private_key,
                                          certificate.subject_enc_key,
                                          payload.cipher)

        isd_as_raw = isd_as.pack()
        mapping = self._session_drkeys_map[payload.session_id]
        hop, _ = mapping[1][isd_as_raw]
        mapping[1][isd_as_raw] = (hop, session_key)
        self._drkey_key_requests.put((payload.session_id, None))

    def handle_drkey_send(self, pkt):
        """
        Handle a packet containing DRKeySendKeys as payload.

        Receive DRKeys for a given session.
        In return send the src_drkey to acknowledge.

        :param pkt: packet containing the send payload
        :type pkt: SCIONL4Packet
        """
        payload = pkt.get_payload()
        assert isinstance(payload, DRKeySendKeys)

        isd_as = pkt.addrs.src.isd_as

        # check certificate chain
        certificate = payload.certificate_chain.certs[0]
        trc = self.trust_store.get_trc(isd_as[0], certificate.version)
        if not payload.certificate_chain.verify(str(pkt.addrs.src.host), trc,
                                                certificate.version):
            logging.info("DRKey with invalid certificate chain from %s."
                         "\nCertificate Chain:%s\nTRC version:%s",
                         pkt.addrs.src, payload.certificate_chain,
                         certificate.version)
            return

        # check signature
        msg = b"".join([payload.cipher, payload.session_id])
        if not verify(msg, payload.signature, certificate.subject_sig_key):
            logging.info("DRKey with invalid signature from %s", pkt.addrs.src)
            return

        # get drkeys
        key_list = key_list_from_bytes(
            decrypt_session_key(self._private_key, certificate.subject_enc_key,
                                payload.cipher))
        drkeys = DRKeys.from_bytes_list(
            key_list, self._get_remote_drkey(payload.session_id))
        self._drkeys_remote[payload.session_id] = drkeys

        # reply
        cipher = encrypt_session_key(self._private_key,
                                     certificate.subject_enc_key,
                                     drkeys.src_key)
        signature = sign(b"".join([cipher, payload.session_id]),
                         self._private_key)
        pkt.reverse()
        assert drkeys.src_key
        cert = self.create_fake_cert_chain()
        payload = DRKeyAcknowledgeKeys.from_values(payload.session_id, cipher,
                                                   signature, cert)
        pkt.set_payload(payload)
        self.send(pkt, pkt.addrs.dst.host, pkt.l4_hdr.dst_port)

    def handle_drkey_ack(self, pkt):
        """
        Handle a packet containing DRKeysAcknowledgeKeys as payload.

        Receive the src_drkey and add it to the mapping.

        :param pkt: packet containing the acknowledgment
        :type pkt: SCIONL4Packet
        """
        payload = pkt.get_payload()
        assert isinstance(payload, DRKeyAcknowledgeKeys)

        isd_as = pkt.addrs.src.isd_as

        # check certificate chain
        certificate = payload.certificate_chain.certs[0]
        trc = self.trust_store.get_trc(isd_as[0], certificate.version)
        if not payload.certificate_chain.verify(str(pkt.addrs.src.host), trc,
                                                certificate.version):
            logging.info("DRKey with invalid certificate chain from %s."
                         "\nCertificate Chain:%s\nTRC version:%s",
                         pkt.addrs.src, payload.certificate_chain,
                         certificate.version)
            return

        # check signature
        msg = b"".join([payload.cipher, payload.session_id])
        if not verify(msg, payload.signature, certificate.subject_sig_key):
            logging.info("DRKey with invalid signature from %s", pkt.addrs.src)
            return

        session_key = decrypt_session_key(self._private_key,
                                          certificate.subject_enc_key,
                                          payload.cipher)

        mapping = self._drkeys_local[payload.session_id]
        if not mapping:
            logging.info("Received DRKey ack for non-existing session_id: %s "
                         "from %s", payload.session_id, pkt.addrs.src)
            return
        self._drkeys_local[payload.session_id] = \
            (session_key, mapping[1], mapping[2], True)
        self._drkey_send_requests.put((payload.session_id, None))
        self._session_drkeys_map.pop(payload.session_id, None)

    def handle_drkey_cc_req(self, pkt):
        """
        Handle a packet containing DRKeyRequestCertChain as payload.

        Reply with the Certificate Chain.

        :param pkt: packet containing the request
        :type pkt: SCIONL4Packet
        """
        pkt.reverse()
        pkt.set_payload(DRKeyReplyCertChain.from_values(
            self.create_fake_cert_chain()))
        self.send(pkt, pkt.addrs.dst.host, pkt.l4_hdr.dst_port)

    def handle_drkey_cc_rep(self, pkt):
        """
        Handle a packet containing DRKeyReplyCertChain as payload.

        Add Certificate Chain to _drkeys_local.

        :param pkt: packet containing the reply
        :type pkt: SCIONL4Packet
        """

        logging.debug("received drkey cc reply: %s", pkt)
        payload = pkt.get_payload()
        assert isinstance(payload, DRKeyReplyCertChain)

        isd_as = pkt.addrs.src.isd_as
        trc = self.trust_store.get_trc(isd_as[0])
        if not payload.certificate_chain.verify(str(pkt.addrs.src.host), trc,
                                                trc.version):
            logging.info("Invalid certificate chain from %s", pkt.addrs.src)
            return

        host = str(pkt.addrs.src.host)
        self._drkey_cert_chains[host] = payload.certificate_chain
        self._drkey_cert_chain_requests.put((host, None))

    def _send_to_next_hop(self, pkt):
        """
        Sends the packet to the next hop on the path.
        If path is EmptyPath it is sent to one random interface.

        :param pkt: The packet
        :type pkt: SCIONL4Packet
        """
        next_hop, port = self.get_first_hop(pkt)
        assert next_hop is not None
        logging.info("Sending packet via (%s:%s):\n%s", next_hop, port, pkt)
        self.send(pkt, next_hop, port)

    def create_fake_cert_chain(self):
        """
        Create a fake end-host CertificateChain
        using the AS key in the topology files.

        :returns: a valid CertificateChain
        :rtype: CertificateChain
        """
        # TODO replace with original certificate when ready !!!!

        cc = self.trust_store.get_cert(self.addr.isd_as)

        if not cc:
            trc = self.trust_store.get_trc(self.addr.isd_as[0])
            assert isinstance(trc, TRC)
            issuer = trc.core_ases[str(self.addr.isd_as)]
            cc = CertificateChain()
            cc.certs.append(issuer)
        else:
            issuer = cc.certs[0]
            cc = CertificateChain(cc.pack().decode('utf-8'))

        cert = Certificate.from_dict(issuer.get_cert_dict(True))
        cert.subject = str(self.addr.host)
        cert.subject_sig_key = SigningKey(self._private_key).verify_key.encode()
        cert.subject_enc_key = generate_enc_pub_key(self._private_key)

        issuer_key = base64.b64decode(
            read_file(get_sig_key_file_path(self.conf_dir)))
        signature = sign(cert.__str__(False).encode('utf-8'), issuer_key)
        cert.signature = signature
        cc.certs.insert(0, cert)

        return cc

    def _choose_opt_path(self, paths):
        """
        Choose a path from a list of paths.

        :param paths: list of paths
        :type paths: [PathBase]
        :returns: a path
        :rtype: PathBase
        """
        # TODO replace by more sophisticated algorithm
        if paths:
            return paths[0]
        else:
            return None


def key_list_from_bytes(raw):
    """
    Split bytes into a list of keys

    :param raw: a blob of bytes, containing the keys
    :type raw: bytes
    :return: [bytes]
    """
    data = Raw(raw)
    key_list = []

    while len(data) > 0:
        key_list.append(data.pop(DRKeyConstants.DRKEY_BYTE_LENGTH))
    return key_list


def bytes_from_key_list(key_list):
    """
    Join list of keys into bytes

    :param key_list: list of drkeys
    :type key_list: [bytes]
    :return: bytes
    """
    return b"".join(key_list)


class SessionNotAvailableError(Exception):
    def __str__(self):
        return "Session not available. " \
               "Provide dst and path to start drkey exchange"
