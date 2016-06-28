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
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    SIBRA_SERVICE,
)
from lib.packet.host_addr import HostAddrSVC


class SVCType(object):
    """
    Defines the recognised SVC addresses.

    `U` suffix stands for Unicast. It's used when the packet should go to a
    single instance of that service.
    `M` suffix stands for Multicast. It's used when the packet should go to all
    instances of that services.
    """
    # Beacon service
    BS_U = HostAddrSVC(0, raw=False)
    BS_M = HostAddrSVC(0 | HostAddrSVC.MCAST, raw=False)
    # Path service
    PS_U = HostAddrSVC(1, raw=False)
    # Certificate service
    CS_U = HostAddrSVC(2, raw=False)
    # SIBRA service
    SB_U = HostAddrSVC(3, raw=False)

SVC_TO_SERVICE = {
    SVCType.BS_U.addr: BEACON_SERVICE,
    SVCType.BS_M.addr: BEACON_SERVICE,
    SVCType.PS_U.addr: PATH_SERVICE,
    SVCType.CS_U.addr: CERTIFICATE_SERVICE,
    SVCType.SB_U.addr: SIBRA_SERVICE,
}

SERVICE_TO_SVC_U = {
    BEACON_SERVICE: SVCType.BS_U,
    CERTIFICATE_SERVICE: SVCType.CS_U,
    PATH_SERVICE: SVCType.PS_U,
    SIBRA_SERVICE: SVCType.SB_U,
}
