#!/usr/bin/python3
# Copyright 2017 ETH Zurich
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
:mod:`sciond` --- Wrapper over low level SCIOND API
===================================================
"""
# Stdlib
import logging
import threading
import time
from contextlib import closing

# External
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import SCION_UDP_EH_DATA_PORT
from lib.errors import SCIONBaseError, SCIONIOError, SCIONParseError
from lib.packet.svc import SVC_TO_SERVICE
from lib.sciond_api.as_req import SCIONDASInfoRequest
from lib.sciond_api.br_req import SCIONDBRInfoRequest
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.parse import parse_sciond_msg
from lib.sciond_api.path_req import SCIONDPathReplyError, SCIONDPathRequest
from lib.sciond_api.revocation import SCIONDRevNotification
from lib.sciond_api.service_req import SCIONDServiceInfoRequest
from lib.socket import ReliableSocket
from lib.types import AddrType, SCIONDMsgType as SMT


# TTL for the ASInfo object (1 hour)
_AS_INFO_TTL = 60 * 60
# TTL for a BR info object (1 hour)
_BR_INFO_TTL = 60 * 60
# TTL for a Service info object (10 seconds)
# TODO(shitz): The TTL for service info objects will be returned by SCIOND in
# the future. At that point, we cannot just statically cache it for a constant
# amount of time.
_SVC_INFO_TTL = 10
# Time after which a request gets retired.
_SCIOND_TO = 5


class SCIONDLibError(SCIONBaseError):
    """Generic SCIOND lib error."""


class SCIONDLibNotInitializedError(SCIONDLibError):
    """SCIOND lib has not been initialized yet."""


class SCIONDConnectionError(SCIONDLibError):
    """Connection to SCIOND failed."""


class SCIONDResponseError(SCIONDLibError):
    """Erroneous reponse from SCIOND."""


class PathRequestFlags:
    def __init__(self, flush=False, sibra=False):
        self.flush = flush
        self.sibra = sibra


class _Counter:
    """Thread-safe counter to generate request IDs."""
    def __init__(self, initial_value=0):
        self._cntr = initial_value
        self._lock = threading.Lock()

    def inc(self):
        """Increases the counter and returns its value."""
        with self._lock:
            self._cntr += 1
            return self._cntr


class SCIONDConnector:
    """Connector class that handles communication to SCIOND."""
    def __init__(self, api_addr):
        self._api_addr = api_addr
        self._req_id = _Counter()
        self._br_infos = ExpiringDict(100, _BR_INFO_TTL)
        self._svc_infos = ExpiringDict(100, _SVC_INFO_TTL)
        self._as_info = None
        self._br_infos_lock = threading.Lock()
        self._svc_infos_lock = threading.Lock()
        self._as_info_lock = threading.Lock()

    def get_paths(self, dst_ia, src_ia, max_paths, flags):
        if not flags:
            flags = PathRequestFlags(flush=False, sibra=False)
        req_id = self._req_id.inc()
        request = SCIONDPathRequest.from_values(
            req_id, dst_ia, src_ia, max_paths, flags.flush, flags.sibra)
        with closing(self._create_socket()) as socket:
            socket.send(request.pack_full())
            response = self._get_response(socket, req_id, SMT.PATH_REPLY)
            if response.p.errorCode != SCIONDPathReplyError.OK:
                raise SCIONDResponseError(
                    SCIONDPathReplyError.describe(response.p.errorCode))
            return list(response.iter_entries())

    def get_as_info(self):
        with self._as_info_lock:
            now = time.time()
            if self._as_info and self._as_info[1] < time.time():
                return self._as_info[0]
            req_id = self._req_id.inc()
            as_req = SCIONDASInfoRequest.from_values(req_id)
            with closing(self._create_socket()) as socket:
                socket.send(as_req.pack_full())
                response = self._get_response(socket, req_id, SMT.AS_REPLY)
            self._as_info = (list(response.iter_entries()), now + _AS_INFO_TTL)
            return self._as_info[0]

    def get_br_info(self, if_list=None):
        with self._br_infos_lock:
            if not if_list:
                if_list = []
            else:
                br_infos = self._try_cache(self._br_infos, if_list)
                if len(br_infos) == len(if_list):
                    return br_infos
                if_list = list(set(if_list) - br_infos.keys())
            req_id = self._req_id.inc()
            br_req = SCIONDBRInfoRequest.from_values(req_id, if_list)
            with closing(self._create_socket()) as socket:
                socket.send(br_req.pack_full())
                response = self._get_response(socket, req_id, SMT.BR_REPLY)
            entries = list(response.iter_entries())
            for entry in entries:
                self._br_infos[entry.p.ifID] = entry
            return entries

    def get_service_info(self, service_types=None):
        with self._svc_infos_lock:
            if not service_types:
                service_types = []
            else:
                svc_infos = self._try_cache(self._svc_infos, service_types)
                if len(svc_infos) == len(service_types):
                    return svc_infos
                service_types = list(
                    set(service_types) - set(svc_infos.keys()))
            req_id = self._req_id.inc()
            svc_req = SCIONDServiceInfoRequest.from_values(
                req_id, service_types)
            with closing(self._create_socket()) as socket:
                socket.send(svc_req.pack_full())
                response = self._get_response(socket, req_id, SMT.SERVICE_REPLY)
            entries = list(response.iter_entries())
            for entry in entries:
                self._svc_infos[entry.service_type()] = entry
            return entries

    def get_next_hop_overlay_dest(self, spkt):
        if_id = spkt.get_fwd_ifid()
        if if_id:
            return self._resolve_ifid(if_id)
        return self._resolve_dst_addr(spkt.addrs.dst)

    def _resolve_ifid(self, if_id):
        br_info = self._br_infos.get(if_id)
        if br_info:
            return br_info.host_info()
        br_infos = self.get_br_info([if_id])
        if br_infos:
            return br_infos[0].host_info()
        return None

    def _resolve_dst_addr(self, dst):
        as_info = self.get_as_info()
        if not as_info:
            return None
        if dst.isd_as != as_info[0].isd_as():
            logging.error("Packet to remote AS w/o path, dst: %s", dst)
            return None
        host = dst.host
        if host.TYPE == AddrType.SVC:
            svc_type = SVC_TO_SERVICE[host.addr]
            svc_info = self._svc_infos.get(svc_type)
            if svc_info:
                return svc_info.host_info()
            svc_infos = self.get_service_info([svc_type])
            if svc_infos:
                return svc_infos[0].host_info()
            return None
        return HostInfo.from_values([host], SCION_UDP_EH_DATA_PORT)

    def send_rev_notification(self, rev_info):
        rev_not = SCIONDRevNotification.from_values(
            self._req_id.inc(), rev_info)
        with closing(self._create_socket()) as socket:
            socket.send(rev_not.pack_full())

    def _create_socket(self):
        socket = ReliableSocket()
        socket.settimeout(_SCIOND_TO)
        try:
            socket.connect(self._api_addr)
        except OSError:
            raise SCIONDConnectionError()
        return socket

    def _get_response(self, socket, expected_id, expected_type):
        try:
            data = socket.recv()[0]
        except socket.timeout:
            raise SCIONDResponseError("Socket timed out.")
        except SCIONIOError:
            raise SCIONDResponseError("Socket IO error.")
        if not data:
            raise SCIONDResponseError("Received empty response from SCIOND.")
        try:
            response = parse_sciond_msg(data)
        except SCIONParseError as e:
            raise SCIONDResponseError(str(e))
        if response.MSG_TYPE != expected_type:
            raise SCIONDResponseError(
                "Unexpected SCIOND msg type received: %s" % response.NAME)
        if response.id != expected_id:
            raise SCIONDResponseError("Wrong response ID: %d (expected %d)" %
                                      (response.id, expected_id))
        return response

    def _try_cache(self, cache, key_list):
        result = {}
        for key in key_list:
            if key in cache:
                result[key] = cache[key]
        return result


_connector = None


def init(api_addr):
    """
    Initializes a SCIONDConnector object and returns it to the caller. The
    first time init is called it initializes the global connector object.
    Subsequent calls return a new instance of SCIONDConnector that can be
    passed to the API calls in case applications have a need for multiple
    connectors. Most applications will not have to deal with a SCIONDConnector
    object directly.
    """
    global _connector
    connector = SCIONDConnector(api_addr)
    if not _connector:
        _connector = connector
    return connector


def get_paths(dst_ia, src_ia=None, max_paths=5, flags=None,
              connector=None):
    """
    Request a set of end to end paths from SCIOND.

    :param dst_ia: The destination ISD_AS
    :param src_ia: The source ISD_AS. If None, the default one will be used.
    :param max_paths: The maximum number of paths returned (can be less).
    :param flags: A PathRequestFlags tuple.
    :returns: A list of SCIONDPathReplyEntry objects.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_paths(dst_ia, src_ia, max_paths, flags)


def get_as_info(connector=None):
    """
    Request information about the local AS(es).

    :returns: List of SCIONDASInfoResponseEntry object
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_as_info()


def get_br_info(if_list=None, connector=None):
    """
    Request addresses and ports of border routers.

    :param if_list: The interface IDs of BRs. If unset, all BRs are
        returned.
    :returns: List of SCIONDBRInfoReplyEntry objects.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_br_info(if_list)


def get_service_info(service_types=None, connector=None):
    """
    Request addresses and ports of infrastructure services.

    :param service_types: The types of the services. If unset, all services
        are returned.
    :returns: List of SCIONDServiceInfoReplyEntry objects.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_service_info(service_types)


def get_next_hop_overlay_dest(spkt, connector=None):
    """
    Returns the HostInfo object of the next hop for a given packet.

    :param spkt: The SCIONPacket object.
    :returns: A HostInfo object containing the first hop.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    fh_info = connector.get_next_hop_overlay_dest(spkt)
    if not fh_info:
        raise SCIONDResponseError("Next hop could not be resolved.")
    return fh_info


def send_rev_notification(rev_info, connector=None):
    """Forwards the RevocationInfo object to SCIOND."""
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    connector.send_rev_notification(rev_info)
