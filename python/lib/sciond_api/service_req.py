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
:mod:`service_req` --- SCIOND Service requests and replies
==========================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.sciond_api.host_info import HostInfo


class SCIONDServiceInfoRequest(Cerealizable):
    NAME = "ServiceInfoRequest"
    P_CLS = P.ServiceInfoRequest

    @classmethod
    def from_values(cls, service_types=None):
        """
        Creates an SCIONDServiceInfoRequest.

        :param service_types: List of service types. An empty list means all
            service types.
        """
        p = cls.P_CLS.new_message()
        if service_types:
            service_entries = p.init("serviceTypes", len(service_types))
            for i, type_ in enumerate(service_types):
                service_entries[i] = type_
        return cls(p)

    def all_services(self):
        return not self.p.serviceTypes

    def iter_service_types(self):
        for type_ in self.p.serviceTypes:
            yield str(type_)

    def short_desc(self):
        type_str = "ALL" if self.all_services() else str(self.p.serviceTypes)
        return "Service types: %s" % type_str


class SCIONDServiceInfoReply(Cerealizable):
    NAME = "ServiceInfoReply"
    P_CLS = P.ServiceInfoReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p)

    def entry(self, idx):
        return SCIONDServiceInfoReplyEntry(self.p.entries[idx])

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDServiceInfoReplyEntry(entry)

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])


class SCIONDServiceInfoReplyEntry(Cerealizable):
    NAME = "ServiceInfoReplyEntry"
    P_CLS = P.ServiceInfoReplyEntry

    @classmethod
    def from_values(cls, service_type, host_infos, ttl=None):
        p = cls.P_CLS.new_message(serviceType=service_type)
        if ttl:
            p.ttl = ttl
        if host_infos:
            entries = p.init("hostInfos", len(host_infos))
            for i, info in enumerate(host_infos):
                entries[i] = info.p
        return cls(p)

    def service_type(self):
        return str(self.p.serviceType)

    def host_info(self, idx):
        return HostInfo(self.p.hostInfos[idx])

    def iter_host_infos(self):
        for info in self.p.hostInfos:
            return HostInfo(info)

    def short_desc(self):
        ttl_str = "unset"
        if self.p.ttl is not None:
            ttl_str = "%ss" % self.p.ttl
        return "Type: %d TTL: %s Host Infos: %s" % (
            self.p.serviceType, ttl_str,
            ", ".join([info.short_desc() for info in self.iter_host_infos()]))
