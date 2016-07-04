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
:mod:`lib_topology_test` --- SCION topology tests
=================================================
"""
# Stdlib
from collections import defaultdict
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONKeyError
from lib.topology import (
    Element,
    InterfaceElement,
    Topology
)
from test.testcommon import assert_these_calls, create_mock


class TestElementInit(object):
    """
    Unit tests for lib.topology.Element.__init__
    """
    def test_basic(self):
        inst = Element()
        ntools.assert_is_none(inst.addr)
        ntools.assert_is_none(inst.name)

    @patch("lib.topology.haddr_parse_interface", autospec=True)
    def test_addr(self, parse):
        inst = Element("addr")
        parse.assert_called_with("addr")
        ntools.eq_(inst.addr, parse.return_value)

    def test_name(self):
        name = create_mock(["__str__"])
        name.__str__.return_value = "hostname"
        # Call
        inst = Element(name=name)
        # Tests
        ntools.assert_equal(inst.name, "hostname")


class TestInterfaceElementInit(object):
    """
    Unit tests for lib.topology.InterfaceElement.__init__
    """

    @patch("lib.topology.haddr_parse_interface", autospec=True)
    @patch("lib.topology.ISD_AS", autospec=True)
    @patch("lib.topology.Element.__init__", autospec=True)
    def test_full(self, super_init, isd_as, parse):
        intf_dict = {
            'Addr': 'addr', 'IFID': 1, 'ISD_AS': '3-2',
            'LinkType': 'PARENT', 'ToUdpPort': 5, 'UdpPort': 6,
            'ToAddr': 'toaddr', "Bandwidth": 1001, 'MTU': 4242,
        }
        # Call
        inst = InterfaceElement(intf_dict, 'name')
        # Tests
        super_init.assert_called_once_with(inst, 'addr', 'name')
        ntools.eq_(inst.if_id, 1)
        ntools.eq_(inst.isd_as, isd_as.return_value)
        ntools.eq_(inst.link_type, "PARENT")
        ntools.eq_(inst.to_udp_port, 5)
        ntools.eq_(inst.udp_port, 6)
        ntools.eq_(inst.bandwidth, 1001)
        ntools.eq_(inst.mtu, 4242)
        parse.assert_called_once_with("toaddr")
        ntools.eq_(inst.to_addr, parse.return_value)


class TestTopologyParseDict(object):
    """
    Unit tests for lib.topology.Topology.parse_dict
    """
    @patch("lib.topology.ISD_AS", autospec=True)
    def test(self, isd_as):
        topo_dict = {'Core': True, 'ISD_AS': '1-2', 'MTU': 440}
        inst = Topology()
        inst._parse_srv_dicts = create_mock()
        inst._parse_router_dicts = create_mock()
        inst._parse_zk_dicts = create_mock()
        # Call
        inst.parse_dict(topo_dict)
        # Tests
        ntools.eq_(inst.is_core_as, True)
        ntools.eq_(inst.isd_as, isd_as.return_value)
        ntools.eq_(inst.mtu, 440)
        inst._parse_srv_dicts.assert_called_once_with(topo_dict)
        inst._parse_router_dicts.assert_called_once_with(topo_dict)
        inst._parse_zk_dicts.assert_called_once_with(topo_dict)


class TestTopologyParseSrvDicts(object):
    """
    Unit tests for lib.topology.Topology.parse_srv_dicts
    """
    @patch("lib.topology.ServerElement", autospec=True)
    def test(self, server):
        topo_dict = {
            'BeaconServers': {"bs1": "bs1 val"},
            'CertificateServers': {"cs1": "cs1 val"},
            'PathServers': {"ps1": "ps1 val", "ps2": "ps2 val"},
            'SibraServers': {"sb1": "sb1 val"},
        }
        inst = Topology()
        server.side_effect = lambda v, k: "%s-%s" % (k, v)
        # Call
        inst._parse_srv_dicts(topo_dict)
        # Tests
        assert_these_calls(server, [
            call("bs1 val", "bs1"), call("cs1 val", "cs1"),
            call("ps1 val", "ps1"), call("ps2 val", "ps2"),
            call("sb1 val", "sb1"),
        ], any_order=True)
        ntools.eq_(inst.beacon_servers, ["bs1-bs1 val"])
        ntools.eq_(inst.certificate_servers, ["cs1-cs1 val"])
        ntools.eq_(sorted(inst.path_servers),
                   sorted(["ps1-ps1 val", "ps2-ps2 val"]))


class TestTopologyParseRouterDicts(object):
    """
    Unit tests for lib.topology.Topology.parse_router_dicts
    """
    @patch("lib.topology.RouterElement", autospec=True)
    def test(self, router):
        def _mk_router(type_):
            m = create_mock(["interface"])
            m.interface = create_mock(["link_type"])
            m.interface.link_type = type_
            routers[type_].append(m)
            return m
        routers = defaultdict(list)
        router_dict = {
            "er-parent": "PARENT", "er-child": "CHILD",
            "er-peer": "PEER", "er-routing0": "ROUTING",
            "er-routing1": "ROUTING",
        }
        inst = Topology()
        router.side_effect = lambda v, k: _mk_router(v)
        # Call
        inst._parse_router_dicts({"EdgeRouters": router_dict})
        # Tests
        ntools.assert_count_equal(inst.parent_edge_routers, routers["PARENT"])
        ntools.assert_count_equal(inst.child_edge_routers, routers["CHILD"])
        ntools.assert_count_equal(inst.peer_edge_routers, routers["PEER"])
        ntools.assert_count_equal(inst.routing_edge_routers, routers["ROUTING"])


class TestTopologyParseZkDicts(object):
    """
    Unit tests for lib.topology.Topology.parse_zk_dicts
    """
    @patch("lib.topology.haddr_parse_interface", autospec=True)
    def test(self, parse):
        zk_dict = {
            'zk0': {'Addr': 'zkv4', 'Port': 2181},
            'zk1': {'Addr': 'zkv6', 'Port': 2182},
        }
        inst = Topology()
        parse.side_effect = lambda x: x
        # Call
        inst._parse_zk_dicts({"Zookeepers": zk_dict})
        # Tests
        ntools.assert_count_equal(inst.zookeepers,
                                  ["[zkv4]:2181", "[zkv6]:2182"])


class TestTopologyGetAllEdgeRouters(object):
    """
    Unit tests for lib.topology.Topology.get_all_edge_routers
    """
    def test(self):
        topology = Topology()
        topology.parent_edge_routers = [0, 1]
        topology.child_edge_routers = [2]
        topology.peer_edge_routers = [3, 4, 5]
        topology.routing_edge_routers = [6, 7]
        ntools.eq_(topology.get_all_edge_routers(), list(range(8)))


class TestTopologyGetOwnConfig(object):
    """
    Unit tests for lib.topology.Topology.get_own_config
    """
    @patch("lib.topology.Topology.get_all_edge_routers", autospec=True)
    def test_basic(self, _):
        inst = Topology()
        for i in range(4):
            bs = create_mock(["name"])
            bs.name = "bs%d" % i
            inst.beacon_servers.append(bs)
        # Call
        ntools.eq_(inst.get_own_config("bs", "bs3"),
                   inst.beacon_servers[3])

    @patch("lib.topology.Topology.get_all_edge_routers", autospec=True)
    def test_unknown_type(self, _):
        inst = Topology()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_own_config, "asdf", 1)

    @patch("lib.topology.Topology.get_all_edge_routers", autospec=True)
    def test_unknown_server(self, _):
        inst = Topology()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_own_config, "bs", "name")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
