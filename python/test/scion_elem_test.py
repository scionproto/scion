# Copyright 2018 ETH Zurich
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
:mod:`sciond_test` --- sciond tests
=====================================================
"""
# Stdlib
from unittest.mock import Mock
from test.testcommon import create_mock_full

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path_mgmt.rev_info import RevocationInfo, SignedRevInfo
from lib.packet.proto_sign import ProtoSignType
from lib.packet.scion_addr import ISD_AS
from lib.rev_cache import RevCache
from lib.types import LinkType
from scion_elem.scion_elem import SCIONElement


class TestSCIONElementRevokedInterfaceCheck(object):
    """
    Unit tests for scion_elem.scion_elem.SCIONElement.check_revoked_interface
    """

    def _mk_pcb(self, exp=0):
        ia = [
            {"isdas": ISD_AS("1-ff00:0:300"), "ingress_if": 1, "egress_if": 2},
            {"isdas": ISD_AS("1-ff00:0:301"), "ingress_if": 3, "egress_if": 4}
        ]
        asms = []
        for j in range(len(ia)):
            hof = create_mock_full(
                {'egress_if': ia[j]['egress_if'], 'ingress_if': ia[j]['ingress_if']})
            pcbm = create_mock_full({'hof()': hof})
            asms.append(create_mock_full({
                "isd_as()": ia[j]['isdas'], "pcbm()": pcbm}))
        pcb = create_mock_full(
            {"iter_asms()": asms, "short_desc()": "short desc"})
        return pcb

    def test_not_revoked(self):
        pcb = self._mk_pcb()
        inst = Mock()
        inst.check_revoked_interface = SCIONElement.check_revoked_interface
        ntools.eq_(inst.check_revoked_interface(inst, pcb, RevCache()), True)

    def test_revoked(self):
        pcb = self._mk_pcb()
        inst = Mock()
        rev_info = RevocationInfo.from_values(ISD_AS("1-ff00:0:300"), 1, LinkType.PARENT, 1)
        srev_info = SignedRevInfo.from_values(rev_info.copy().pack(),
                                              ProtoSignType.ED25519, "src".encode())
        rev_cache = Mock()
        rev_cache.get.return_value = srev_info
        inst.check_revoked_interface = SCIONElement.check_revoked_interface
        ntools.eq_(inst.check_revoked_interface(inst, pcb, rev_cache), False)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
