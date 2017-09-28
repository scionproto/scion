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
import os
import random
import threading
from contextlib import closing
from socket import timeout

# External
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import (
    SCION_UDP_EH_DATA_PORT,
    SCIOND_API_DEFAULT_SOCK,
    SCIOND_API_PATH_ENV_VAR,
    SCIOND_API_SOCKDIR,
)
from lib.errors import SCIONBaseError, SCIONIOError, SCIONParseError
from lib.packet.svc import SVC_TO_SERVICE
from lib.sciond_api.base import SCIONDMsg
from lib.sciond_api.as_req import SCIONDASInfoRequest
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.if_req import SCIONDIFInfoRequest
from lib.sciond_api.path_req import SCIONDPathReplyError, SCIONDPathRequest
from lib.sciond_api.revocation import SCIONDRevNotification
from lib.sciond_api.service_req import SCIONDServiceInfoRequest
from lib.socket import ReliableSocket
from lib.types import AddrType, SCIONDMsgType as SMT


# TTL for the ASInfo object (1 hour)
_AS_INFO_TTL = 60 * 60
# TTL for a IF info object (1 hour)
_IF_INFO_TTL = 60 * 60
# TTL for a Service info object (10 seconds)
# TODO(shitz): The TTL for service info objects will be returned by SCIOND in
# the future. At that point, we cannot just statically cache it for a constant
# amount of time.
_SVC_INFO_TTL = 10
# Time after which a request gets retired.
_SCIOND_TOUT = 3


class SCIONDLibError(SCIONBaseError):
    """Generic SCIOND lib error."""


class SCIONDLibNotInitializedError(SCIONDLibError):
    """SCIOND lib has not been initialized yet."""


class SCIONDConnectionError(SCIONDLibError):
    """Connection to SCIOND failed."""


class SCIONDRequestError(SCIONDLibError):
    """Request could not be sent to SCIOND."""


class SCIONDResponseError(SCIONDLibError):
    """Erroneous reponse from SCIOND."""


class PathRequestFlags:  # pragma: no cover
    def __init__(self, flush=False, sibra=False):
        self.flush = flush
        self.sibra = sibra


class _Counter:  # pragma: no cover
    """Thread-safe counter to generate request IDs."""
    def __init__(self, initial_value=0, max_value=2**64 - 1):
        self._cntr = initial_value
        self._max_value = max_value
        self._lock = threading.Lock()

    def inc(self):
        """Increases the counter and returns its value."""
        with self._lock:
            self._cntr += 1
            if self._cntr > self._max_value:
                self._cntr = 0
            return self._cntr


class SCIONDConnector:
    """Connector class that handles communication to SCIOND."""
    def __init__(self, api_addr, counter):  # pragma: no cover
        self._api_addr = api_addr
        self._req_id = counter
        self._if_infos = ExpiringDict(100, _IF_INFO_TTL)
        self._svc_infos = ExpiringDict(100, _SVC_INFO_TTL)
        self._as_infos = ExpiringDict(100, _AS_INFO_TTL)
        self._if_infos_lock = threading.Lock()
        self._svc_infos_lock = threading.Lock()
        self._as_infos_lock = threading.Lock()

    def get_paths(self, dst_ia, src_ia, max_paths, flags=None):
        if not flags:
            flags = PathRequestFlags(flush=False, sibra=False)
        req_id = self._req_id.inc()
        request = SCIONDMsg(SCIONDPathRequest.from_values(
            dst_ia, src_ia, max_paths, flags.flush, flags.sibra), req_id)
        with closing(self._create_socket()) as socket:
            if not socket.send(request.pack()):
                raise SCIONDRequestError
            response = self._get_response(socket, req_id, SMT.PATH_REPLY)
            if response.p.errorCode != SCIONDPathReplyError.OK:
                raise SCIONDResponseError(
                    SCIONDPathReplyError.describe(response.p.errorCode))
            return list(response.iter_entries())

    def get_as_info(self, isd_as=None):
        q_ia = isd_as
        if not q_ia:
            q_ia = "local"
        with self._as_infos_lock:
            _, as_infos = self._try_cache(self._as_infos, [q_ia])
            as_info = as_infos.get(q_ia)
            if as_info:
                return as_info
            req_id = self._req_id.inc()
            as_req = SCIONDMsg(SCIONDASInfoRequest.from_values(isd_as), req_id)
            with closing(self._create_socket()) as socket:
                if not socket.send(as_req.pack()):
                    raise SCIONDRequestError
                response = self._get_response(socket, req_id, SMT.AS_REPLY)
            self._as_infos[q_ia] = list(response.iter_entries())
            return self._as_infos[q_ia]

    def get_if_info(self, if_list=None):
        with self._if_infos_lock:
            if if_list:
                if_list, if_infos = self._try_cache(self._if_infos, if_list)
                if not if_list:
                    # The request could be satisfied with cached IF infos.
                    return if_infos
            else:
                if_infos = {}
                if_list = set()
            # Request missing IF infos.
            req_id = self._req_id.inc()
            if_req = SCIONDMsg(SCIONDIFInfoRequest.from_values(if_list), req_id)
            with closing(self._create_socket()) as socket:
                if not socket.send(if_req.pack()):
                    raise SCIONDRequestError
                response = self._get_response(socket, req_id, SMT.IF_REPLY)
            for entry in response.iter_entries():
                self._if_infos[entry.p.ifID] = entry
                if_infos[entry.p.ifID] = entry
            return if_infos

    def get_service_info(self, service_types=None):
        with self._svc_infos_lock:
            if service_types:
                service_types, svc_infos = self._try_cache(self._svc_infos, service_types)
                if not service_types:
                    # The request could be satisfied with cached IF infos.
                    return svc_infos
            else:
                svc_infos = {}
                service_types = set()
            # Request missing service infos.
            req_id = self._req_id.inc()
            svc_req = SCIONDMsg(SCIONDServiceInfoRequest.from_values(service_types), req_id)
            with closing(self._create_socket()) as socket:
                if not socket.send(svc_req.pack()):
                    raise SCIONDRequestError
                response = self._get_response(socket, req_id, SMT.SERVICE_REPLY)
            for entry in response.iter_entries():
                self._svc_infos[entry.service_type()] = entry
                svc_infos[entry.service_type()] = entry
            return svc_infos

    def get_overlay_dest(self, spkt):  # pragma: no cover
        if_id = spkt.get_fwd_ifid()
        if if_id:
            return self._resolve_ifid(if_id)
        return self._resolve_dst_addr(spkt.addrs.src, spkt.addrs.dst)

    def _resolve_ifid(self, if_id):  # pragma: no cover
        if_infos = self.get_if_info([if_id])
        if if_id in if_infos:
            return if_infos[if_id].host_info()
        return None

    def _resolve_dst_addr(self, src, dst):
        if dst.isd_as != src.isd_as:
            logging.error("Packet to remote AS w/o path, dst: %s", dst)
            return None
        host = dst.host
        if host.TYPE == AddrType.SVC:
            svc_type = SVC_TO_SERVICE[host.addr]
            svc_infos = self.get_service_info([svc_type])
            if svc_type in svc_infos:
                return svc_infos[svc_type].host_info(0)
            return None
        return HostInfo.from_values([host], SCION_UDP_EH_DATA_PORT)

    def send_rev_notification(self, rev_info):  # pragma: no cover
        rev_not = SCIONDMsg(SCIONDRevNotification.from_values(rev_info), self._req_id.inc())
        with closing(self._create_socket()) as socket:
            if not socket.send(rev_not.pack()):
                raise SCIONDRequestError

    def _create_socket(self):  # pragma: no cover
        socket = ReliableSocket()
        socket.settimeout(_SCIOND_TOUT)
        try:
            socket.connect(self._api_addr)
        except OSError as e:
            socket.close()
            raise SCIONDConnectionError(str(e))
        return socket

    def _get_response(self, socket, expected_id, expected_type):  # pragma: no cover
        try:
            data = socket.recv()[0]
        except timeout:
            raise SCIONDResponseError("Socket timed out.")
        except SCIONIOError:
            raise SCIONDResponseError("Socket IO error.")
        if not data:
            raise SCIONDResponseError("Received empty response from SCIOND.")
        try:
            response = SCIONDMsg.from_raw(data)
        except SCIONParseError as e:
            raise SCIONDResponseError(str(e))
        if response.type() != expected_type:
            raise SCIONDResponseError(
                "Unexpected SCIOND msg type received: %s" % response.NAME)
        if response.id != expected_id:
            raise SCIONDResponseError("Wrong response ID: %d (expected %d)" %
                                      (response.id, expected_id))
        return response.union

    @staticmethod
    def _try_cache(cache, key_list):
        """
        Returns items from cache whose keys are in key_list.

        :param cache: The cache to check.
        :param key_list: The list of keys to check for.
        :returns: A set containg all keys that couldn't be found in the cache
            and a dict mapping from keys to items that were contained in the cache.
        """
        key_set = set(key_list)
        result = {}
        for key in key_list:
            if key in cache:
                result[key] = cache[key]
        key_set -= set(result)
        return key_set, result


_connector = None
_counter = None


def init(api_addr=None):  # pragma: no cover
    """
    Initializes a SCIONDConnector object and returns it to the caller. The
    first time init is called it initializes the global connector object.
    Subsequent calls return a new instance of SCIONDConnector that can be
    passed to the API calls in case applications have a need for multiple
    connectors. Most applications will not have to deal with a SCIONDConnector
    object directly.
    """
    global _connector
    global _counter
    if not _counter:
        _counter = _Counter(random.randint(0, 2**32 - 1))
    api_addr = api_addr or _get_api_addr()
    connector = SCIONDConnector(api_addr, _counter)
    if not _connector:
        _connector = connector
    return connector


def _get_api_addr():  # pragma: no cover
    return os.getenv(SCIOND_API_PATH_ENV_VAR,
                     os.path.join(SCIOND_API_SOCKDIR, SCIOND_API_DEFAULT_SOCK))


def get_paths(dst_ia, src_ia=None, max_paths=5, flags=None, connector=None):  # pragma: no cover
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


def get_as_info(isd_as=None, connector=None):  # pragma: no cover
    """
    Request information about the local AS(es).

    :param isd_as: The ISD_AS for which the info is requested. If unset, the
        local AS info is requested.
    :returns: List of SCIONDASInfoResponseEntry object
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_as_info()


def get_if_info(if_list=None, connector=None):  # pragma: no cover
    """
    Request addresses and ports of interfaces.

    :param if_list: The interface IDs of BRs. If empty, all interfaces are
        returned.
    :returns: Dict that maps from if_id to SCIONDIFInfoReplyEntry objects.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_if_info(if_list)


def get_service_info(service_types=None, connector=None):  # pragma: no cover
    """
    Request addresses and ports of infrastructure services.

    :param service_types: The types of the services. If unset, all services
        are returned.
    :returns: Dict that maps from service type to SCIONDServiceInfoReplyEntry
        objects.
    """
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    return connector.get_service_info(service_types)


def get_overlay_dest(spkt, connector=None):  # pragma: no cover
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
    fh_info = connector.get_overlay_dest(spkt)
    if not fh_info:
        raise SCIONDResponseError("Next hop could not be resolved.")
    return fh_info


def send_rev_notification(rev_info, connector=None):  # pragma: no cover
    """Forwards the RevocationInfo object to SCIOND."""
    global _connector
    if not connector:
        connector = _connector
    if not connector:
        raise SCIONDLibNotInitializedError
    connector.send_rev_notification(rev_info)
