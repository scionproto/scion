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
        ntools.assert_equal(inst.public, [])
        ntools.assert_is_none(inst.name)

    @patch("lib.topology.haddr_parse_interface", autospec=True)
    def test_public(self, parse):
        public = {'Addr': 'addr', 'L4Port': 'port'}
        inst = Element(public)
        parse.assert_called_with("addr")
        ntools.eq_(inst.public[0][0], parse.return_value)

    @patch("lib.topology.haddr_parse_interface", autospec=True)
    def test_bind(self, parse):
        bind = {'Addr': 'addr', 'L4Port': 'port'}
        inst = Element(bind=bind)
        parse.assert_called_with("addr")
        ntools.eq_(inst.bind[0][0], parse.return_value)

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
            'InternalAddrIdx': 0,
            'Overlay': 'UDP/IPv4',
            'Public': {
                'Addr': 'addr',
                'L4Port': 6
            },
            'Remote': {
                'Addr': 'toaddr',
                'L4Port': 5
            },
            'Bandwidth': 1001,
            'ISD_AS': '3-ff00:0:301',
            'LinkType': 'PARENT',
            'MTU': 4242
        }
        if_id = 1
        public = {'Addr': 'addr', 'L4Port': 6}
        # Call
        inst = InterfaceElement(if_id, intf_dict, 'name')
        # Tests
        super_init.assert_called_once_with(inst, public, None, 'name')
        ntools.eq_(inst.if_id, 1)
        ntools.eq_(inst.isd_as, isd_as.return_value)
        ntools.eq_(inst.link_type, "PARENT")
        ntools.eq_(inst.bandwidth, 1001)
        ntools.eq_(inst.mtu, 4242)
        ntools.eq_(inst.overlay, "UDP/IPv4")
        parse.assert_called_once_with("toaddr")
        ntools.eq_(inst.remote[0], (parse.return_value, 5))


class TestTopologyParseDict(object):
    """
    Unit tests for lib.topology.Topology.parse_dict
    """
    @patch("lib.topology.ISD_AS", autospec=True)
    def test(self, isd_as):
        topo_dict = {'Core': True, 'ISD_AS': '1-ff00:0:312', 'MTU': 440, 'Overlay': 'UDP/IPv4'}
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
            'BeaconService': {"bs1": "bs1 val"},
            'CertificateService': {"cs1": "cs1 val"},
            'PathService': {"ps1": "ps1 val", "ps2": "ps2 val"},
            'SibraService': {"sb1": "sb1 val"},
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
            m = create_mock(["interfaces"])
            m.interfaces = {0: create_mock(["link_type"])}
            m.interfaces[0].link_type = type_
            routers[type_].append(m)
            return m
        routers = defaultdict(list)
        router_dict = {"br-parent": "PARENT"}
        inst = Topology()
        router.side_effect = lambda v, k: _mk_router(v)
        # Call
        inst._parse_router_dicts({"BorderRouters": router_dict})
        # Tests
        ntools.assert_count_equal(inst.border_routers, routers["PARENT"])


class TestTopologyParseZkDicts(object):
    """
    Unit tests for lib.topology.Topology.parse_zk_dicts
    """
    @patch("lib.topology.haddr_parse_interface", autospec=True)
    def test(self, parse):
        zk_dict = {
            'zk0': {'Addr': 'zkv4', 'L4Port': 2181},
            'zk1': {'Addr': 'zkv6', 'L4Port': 2182},
        }
        inst = Topology()
        parse.side_effect = lambda x: x
        # Call
        inst._parse_zk_dicts({"ZookeeperService": zk_dict})
        # Tests
        ntools.assert_count_equal(inst.zookeepers,
                                  ["[zkv4]:2181", "[zkv6]:2182"])


class TestTopologyGetAllInterfaces(object):
    """
    Unit tests for lib.topology.Topology.get_all_border_routers
    """
    def test(self):
        topology = Topology()
        topology.parent_interfaces = [0, 1]
        topology.child_interfaces = [2]
        topology.peer_interfaces = [3, 4, 5]
        topology.core_interfaces = [6, 7]
        ntools.eq_(topology.get_all_interfaces(), list(range(8)))


class TestTopologyGetOwnConfig(object):
    """
    Unit tests for lib.topology.Topology.get_own_config
    """
    def test_basic(self):
        inst = Topology()
        for i in range(4):
            bs = create_mock(["name"])
            bs.name = "bs%d" % i
            inst.beacon_servers.append(bs)
        # Call
        ntools.eq_(inst.get_own_config("bs", "bs3"),
                   inst.beacon_servers[3])

    def test_unknown_type(self):
        inst = Topology()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_own_config, "asdf", 1)

    def test_unknown_server(self):
        inst = Topology()
        # Call
        ntools.assert_raises(SCIONKeyError, inst.get_own_config, "bs", "name")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
