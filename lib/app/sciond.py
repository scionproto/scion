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
# External
from external.expiring_dict import ExpiringDict

# SCION
from lib.defines import SCION_UDP_EH_DATA_PORT
from lib.errors import SCIONBaseError, SCIONParseError
from lib.packet.svc import SVC_TO_SERVICE
from lib.sciond_api.as_req import SCIONDASInfoRequest
from lib.sciond_api.br_req import SCIONDBRInfoRequest
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.parse import parse_sciond_msg
from lib.sciond_api.path_req import SCIONDPathReplyError, SCIONDPathRequest
from lib.sciond_api.service_req import SCIONDServiceInfoRequest
from lib.socket import ReliableSocket
from lib.types import AddrType, SCIONDMsgType as SMT


class SCIONDConnectorError(SCIONBaseError):
    """Generic SCIONDConnectorError."""


class SCIONDConnectionError(SCIONDConnectorError):
    """Connection to SCIOND failed."""


class SCIONDResponseError(SCIONDConnectorError):
    """Erroneous reponse from SCIOND."""


class PathRequestFlags:
    def __init__(self, flush=False, sibra=False):
        self.flush = flush
        self.sibra = sibra


class SCIONDConnector:
    """Connector to SCIOND for applications. Not thread-safe!"""
    def __init__(self, api_addr):
        self._api_addr = api_addr
        self._socket = None
        self._req_id = 0
        self._br_infos = ExpiringDict(100, 10)
        self._svc_infos = ExpiringDict(100, 10)
        self._setup_socket()

    def _setup_socket(self):
        self._socket = ReliableSocket()
        try:
            self._socket.connect(self._api_addr)
        except OSError:
            raise SCIONDConnectionError()

    def _get_response(self, expected_type):
        data = self._socket.recv()[0]
        if not data:
            raise SCIONDResponseError("Received empty response from SCIOND.")
        try:
            response = parse_sciond_msg(data)
        except SCIONParseError as e:
            raise SCIONDResponseError(str(e))
        if response.MSG_TYPE != expected_type:
            raise SCIONDResponseError(
                "Unexpected SCIOND msg type received: %s" % response.NAME)
        return response

    def _try_cache(self, cache, key_list):
        result = []
        for key in key_list:
            if key in cache:
                result.append(cache[key])
        return result

    def get_path(self, dst_ia, src_ia=None, max_paths=5, flags=None):
        """
        Request a set of end to end paths from SCIOND.

        :param dst_ia: The destination ISD_AS
        :param src_ia: The source ISD_AS. If None, the default one will be used.
        :param max_paths: The maximum number of paths returned (can be less).
        :param flags: A PathRequestFlags tuple.
        :returns: A list of SCIONDPathReplyEntry objects.
        """
        if not flags:
            flags = PathRequestFlags(flush=False, sibra=False)
        request = SCIONDPathRequest.from_values(
            self._req_id, dst_ia, src_ia, max_paths, flags.flush, flags.sibra)
        self._socket.send(request.pack_full())
        response = self._get_response(SMT.PATH_REPLY)
        if response.p.id != self._req_id:
            raise SCIONDResponseError("Wrong response ID: %d (expected %d)" %
                                      (response.p.id, self._req_id))
        if response.p.errorCode != SCIONDPathReplyError.OK:
            raise SCIONDResponseError(
                SCIONDPathReplyError.describe(response.p.errorCode))
        self._req_id += 1
        return list(response.iter_entries())

    def get_as_info(self):
        """
        Request information about the local AS(es).

        :returns: List of SCIONDASInfoResponseEntry object
        """
        as_req = SCIONDASInfoRequest.from_values()
        self._socket.send(as_req.pack_full())
        response = self._get_response(SMT.AS_REPLY)
        return list(response.iter_entries())

    def get_br_info(self, if_list=None):
        """
        Request addresses and ports of border routers.

        :param if_list: The interface IDs of BRs. If unset, all BRs are
            returned.
        :returns: List of SCIONDBRInfoReplyEntry objects.
        """
        if not if_list:
            if_list = []
        else:
            br_infos = self._try_cache(self._br_infos, if_list)
            if len(br_infos) == len(if_list):
                return br_infos
        br_req = SCIONDBRInfoRequest.from_values(if_list)
        self._socket.send(br_req.pack_full())
        response = self._get_response(SMT.BR_REPLY)
        entries = list(response.iter_entries())
        for entry in entries:
            self._br_infos[entry.p.ifID] = entry
        return entries

    def get_service_info(self, service_types=None):
        """
        Request addresses and ports of infrastructure services.

        :param service_types: The types of the services. If unset, all services
            are returned.
        :returns: List of SCIONDServiceInfoReplyEntry objects.
        """
        if not service_types:
            service_types = []
        else:
            svc_infos = self._try_cache(self._svc_infos, service_types)
            if len(svc_infos) == len(service_types):
                return svc_infos
        svc_req = SCIONDServiceInfoRequest.from_values(service_types)
        self._socket.send(svc_req.pack_full())
        response = self._get_response(SMT.SERVICE_REPLY)
        entries = list(response.iter_entries())
        for entry in entries:
            self._svc_infos[entry.service_type()] = entry
        return entries

    def get_first_hop(self, spkt):
        """
        Returns the HostInfo object of the first hop for a given packet.

        :param spkt: The SCIONPacket object.
        """
        return self._get_first_hop(spkt.path, spkt.addrs.dst, spkt.ext_hdrs)

    def _get_first_hop(self, path, dst, ext_hdrs=()):
        if_id = self._ext_first_hop(ext_hdrs)
        if if_id is None:
            if len(path) == 0:
                return self._empty_first_hop(dst)
            if_id = path.get_fwd_if()
        if if_id in self._br_infos:
            return self._br_infos[if_id].host_info()
        return self.get_br_info([if_id])[0].host_info()

    def _ext_first_hop(self, ext_hdrs):
        for hdr in ext_hdrs:
            if_id = hdr.get_next_ifid()
            if if_id is not None:
                return if_id

    def _empty_first_hop(self, dst):
        host = dst.host
        if host.TYPE == AddrType.SVC:
            svc_type = SVC_TO_SERVICE[host.addr]
            if svc_type in self._svc_infos:
                return self._svc_infos[svc_type].host_info()
            return self.get_service_info([svc_type])[0].host_info()
        return HostInfo.from_values([host], SCION_UDP_EH_DATA_PORT)
