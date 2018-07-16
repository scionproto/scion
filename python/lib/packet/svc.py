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
:mod:`svc` --- Service addresses
================================
"""
# SCION
from lib.packet.host_addr import HostAddrSVC
from lib.types import ServiceType


class SVCType(object):
    """
    Defines the recognised SVC addresses.

    `A` suffix stands for Anycast. It indicates the packet should go to a single
    instance of that service.
    `M` suffix stands for Multicast. It indicates the packet should go to all
    instances of that service.
    """
    # Beacon service
    BS_A = HostAddrSVC(0, raw=False)
    BS_M = HostAddrSVC(0 | HostAddrSVC.MCAST, raw=False)
    # Path service
    PS_A = HostAddrSVC(1, raw=False)
    # Certificate service
    CS_A = HostAddrSVC(2, raw=False)
    # SIBRA service
    SB_A = HostAddrSVC(3, raw=False)
    # No service, used e.g., in TCP socket.
    NONE = HostAddrSVC(0xffff, raw=False)

SVC_TO_SERVICE = {
    SVCType.BS_A.addr: ServiceType.BS,
    SVCType.BS_M.addr: ServiceType.BS,
    SVCType.PS_A.addr: ServiceType.PS,
    SVCType.CS_A.addr: ServiceType.CS,
    SVCType.SB_A.addr: ServiceType.SIBRA,
}

SERVICE_TO_SVC_A = {
    ServiceType.BS: SVCType.BS_A,
    ServiceType.CS: SVCType.CS_A,
    ServiceType.PS: SVCType.PS_A,
    ServiceType.SIBRA: SVCType.SB_A,
}
