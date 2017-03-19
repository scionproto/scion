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
:mod:`lib_app_sciond_test` --- lib.app.sciond tests
===================================================
"""
# Stdlib
from unittest.mock import ANY, call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.app.sciond import SCIONDConnector, SCIONDResponseError
from lib.defines import SCION_UDP_EH_DATA_PORT
from lib.packet.host_addr import HostAddrIPv4, HostAddrSVC
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.path_req import SCIONDPathReplyError as PRE
from lib.types import SCIONDMsgType as SMT
from test.testcommon import assert_these_calls, create_mock, create_mock_full


class SCIONDConnectorTestBase:
    def _setup_connector(self, response):
        counter = create_mock_full({"inc()": 1})
        connector = SCIONDConnector("addr", counter)
        connector._create_socket = create_mock()
        connector._get_response = create_mock_full(return_value=response)
        return connector


class TestSCIONDConnectorGetPaths(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_paths"""
    def _create_response(self, entries, with_error):
        p = create_mock_full(
            {"errorCode": PRE.NO_PATHS if with_error else PRE.OK})
        return create_mock_full({"p": p, "iter_entries()": entries})

    def test(self):
        connector = self._setup_connector(
            self._create_response(["1", "2"], False))
        # Call
        paths = connector.get_paths(1, 2, 5)
        # Tests
        ntools.eq_(paths, ["1", "2"])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.PATH_REPLY)

    def test_with_error(self):
        connector = self._setup_connector(
            self._create_response([], True))
        # Call
        with ntools.assert_raises(SCIONDResponseError):
            connector.get_paths(1, 2, 5)
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.PATH_REPLY)


class TestSCIONDConnectorGetASInfo(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_as_info"""
    def _setup(self):
        return self._setup_connector(create_mock_full({"iter_entries()": ["as_info"]}))

    def test_local(self):
        connector = self._setup()
        # Call
        ntools.eq_(connector.get_as_info(), ["as_info"])
        # Tests
        ntools.eq_(connector._as_infos["local"], ["as_info"])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.AS_REPLY)

    def test_remote(self):
        connector = self._setup()
        isd_as = ISD_AS("1-1")
        # Call
        ntools.eq_(connector.get_as_info(isd_as), ["as_info"])
        # Tests
        ntools.eq_(connector._as_infos[isd_as], ["as_info"])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.AS_REPLY)

    def test_with_cache(self):
        connector = self._setup()
        isd_as = ISD_AS("1-1")
        connector._as_infos["local"] = ["as_info1"]
        connector._as_infos[isd_as] = ["as_info2"]
        # Call
        ntools.eq_(connector.get_as_info(), ["as_info1"])
        ntools.eq_(connector.get_as_info(isd_as), ["as_info2"])
        # Tests
        ntools.assert_false(connector._create_socket.called)
        ntools.assert_false(connector._get_response.called)


class TestSCIONDConnectorGetIFInfo(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_if_info"""
    def _create_entries(self, descs):
        response_entries = []
        for desc in descs:
            p = create_mock_full({"ifID": desc[0], "hostInfo": desc[1]})
            response_entries.append(create_mock_full({"p": p, "host_info()": desc[1]}))
        return response_entries

    def test_get_all(self):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_if_info(), {1: entries[0], 2: entries[1]})
        # Tests
        ntools.eq_(connector._if_infos[1], entries[0])
        ntools.eq_(connector._if_infos[2], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.IF_REPLY)

    def test_get(self):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_if_info([1, 2]), {1: entries[0], 2: entries[1]})
        # Tests
        ntools.eq_(connector._if_infos[1], entries[0])
        ntools.eq_(connector._if_infos[2], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.IF_REPLY)

    def test_get_with_cache(self):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(None)
        connector._if_infos = {1: entries[0], 2: entries[1]}
        # Call
        ntools.eq_(connector.get_if_info([1, 2]), {1: entries[0], 2: entries[1]})
        # Tests
        ntools.eq_(connector._if_infos[1], entries[0])
        ntools.eq_(connector._if_infos[2], entries[1])
        ntools.assert_false(connector._create_socket.called)
        ntools.assert_false(connector._get_response.called)

    def test_get_partial_cache(self):
        cached_entries = self._create_entries([(1, "if1"), (2, "if2")])
        response_entries = self._create_entries([(3, "if3")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": response_entries}))
        connector._if_infos = {1: cached_entries[0], 2: cached_entries[1]}
        # Call
        ntools.eq_(connector.get_if_info([1, 2, 3]),
                   {1: cached_entries[0], 2: cached_entries[1], 3: response_entries[0]})
        # Tests
        ntools.eq_(connector._if_infos[1], cached_entries[0])
        ntools.eq_(connector._if_infos[2], cached_entries[1])
        ntools.eq_(connector._if_infos[3], response_entries[0])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.IF_REPLY)

    def test_get_duplicates(self):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_if_info([1, 2, 2, 2]), {1: entries[0], 2: entries[1]})
        # Tests
        ntools.eq_(connector._if_infos[1], entries[0])
        ntools.eq_(connector._if_infos[2], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.IF_REPLY)


class TestSCIONDConnectorGetServiceInfo(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_service_info"""
    def _create_entries(self, descs):
        response_entries = []
        for desc in descs:
            response_entries.append(create_mock_full(
                {"service_type()": desc[0], "host_info()": desc[1]}))
        return response_entries

    def test_get_all(self):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_service_info(), {"bs": entries[0], "ps": entries[1]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], entries[0])
        ntools.eq_(connector._svc_infos["ps"], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SERVICE_REPLY)

    def test_get(self):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps"]),
                   {"bs": entries[0], "ps": entries[1]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], entries[0])
        ntools.eq_(connector._svc_infos["ps"], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SERVICE_REPLY)

    def test_get_with_cache(self):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(None)
        connector._svc_infos = {"bs": entries[0], "ps": entries[1]}
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps"]),
                   {"bs": entries[0], "ps": entries[1]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], entries[0])
        ntools.eq_(connector._svc_infos["ps"], entries[1])
        ntools.assert_false(connector._create_socket.called)
        ntools.assert_false(connector._get_response.called)

    def test_get_partial_cache(self):
        cached_entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        response_entries = self._create_entries([("cs", "cs1")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": response_entries}))
        connector._svc_infos = {"bs": cached_entries[0], "ps": cached_entries[1]}
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps", "cs"]),
                   {"bs": cached_entries[0], "ps": cached_entries[1], "cs": response_entries[0]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], cached_entries[0])
        ntools.eq_(connector._svc_infos["ps"], cached_entries[1])
        ntools.eq_(connector._svc_infos["cs"], response_entries[0])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SERVICE_REPLY)

    def test_get_duplicates(self):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps", "bs", "ps"]),
                   {"bs": entries[0], "ps": entries[1]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], entries[0])
        ntools.eq_(connector._svc_infos["ps"], entries[1])
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SERVICE_REPLY)


class TestSCIONDConnectorGetOverlayDest:
    """Unit tests for lib.app.sciond.SCIONDConnector.get_overlay_dest"""
    def _create_spkt(self, if_id=None, dst=None, src=None):
        addrs = create_mock_full({"dst": dst, "src": src})
        spkt = create_mock_full({"get_fwd_ifid()": if_id, "addrs": addrs})
        return spkt

    def _setup_connector(self, if_info_desc=None, svc_info_desc=None):
        counter = create_mock_full({"inc()": 1})
        connector = SCIONDConnector("addr", counter)
        if if_info_desc:
            if_info = create_mock_full({"host_info()": if_info_desc[1]})
            connector.get_if_info = create_mock_full(return_value={if_info_desc[0]: if_info})
        if svc_info_desc:
            svc_info = create_mock_full({"host_info()": svc_info_desc[1]})
            connector.get_service_info = create_mock_full(
                return_value={svc_info_desc[0]: svc_info})
        return connector

    def test_with_ifid(self):
        spkt = self._create_spkt(if_id=1)
        connector = self._setup_connector(if_info_desc=(1, "host1"))
        # Call
        ntools.eq_(connector.get_overlay_dest(spkt), "host1")
        # Tests
        spkt.get_fwd_ifid.assert_called_once_with()
        connector.get_if_info.assert_called_once_with([1])

    def test_with_svc(self):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-1"), HostAddrSVC(0, raw=False))
        src_addr = SCIONAddr.from_values(ISD_AS("1-1"), HostAddrIPv4("127.0.0.1"))
        spkt = self._create_spkt(dst=dst_addr, src=src_addr)
        connector = self._setup_connector(svc_info_desc=("bs", "bs1"))
        # Call
        ntools.eq_(connector.get_overlay_dest(spkt), "bs1")
        # Tests
        spkt.get_fwd_ifid.assert_called_once_with()
        connector.get_service_info.assert_called_once_with(["bs"])

    def test_with_host(self):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-1"), HostAddrIPv4("127.0.0.2"))
        src_addr = SCIONAddr.from_values(ISD_AS("1-1"), HostAddrIPv4("127.0.0.1"))
        spkt = self._create_spkt(dst=dst_addr, src=src_addr)
        connector = self._setup_connector()
        # Call
        ntools.eq_(connector.get_overlay_dest(spkt),
                   HostInfo.from_values([HostAddrIPv4("127.0.0.2")], SCION_UDP_EH_DATA_PORT))
        # Tests
        spkt.get_fwd_ifid.assert_called_once_with()

    def test_with_different_ases(self):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-2"), HostAddrSVC(0, raw=False))
        src_addr = SCIONAddr.from_values(ISD_AS("1-1"), HostAddrIPv4("127.0.0.1"))
        spkt = self._create_spkt(dst=dst_addr, src=src_addr)
        connector = self._setup_connector(svc_info_desc=("bs", "bs1"))
        # Call
        ntools.eq_(connector.get_overlay_dest(spkt), None)
        # Tests
        spkt.get_fwd_ifid.assert_called_once_with()
        ntools.assert_false(connector.get_service_info.called)
