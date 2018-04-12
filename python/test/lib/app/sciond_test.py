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
from unittest.mock import ANY, patch

# External packages
import nose.tools as ntools

# SCION
from lib.app.sciond import PathRequestFlags, SCIONDConnector, SCIONDResponseError
from lib.defines import SCION_UDP_EH_DATA_PORT
from lib.packet.host_addr import HostAddrIPv4, HostAddrSVC
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.svc import SVCType
from lib.sciond_api.path_req import SCIONDPathReplyError as PRE
from lib.types import (
    PathSegmentType as PST,
    SCIONDMsgType as SMT,
)
from test.testcommon import create_mock, create_mock_full


class SCIONDConnectorTestBase:
    REQ_ID = 1

    def _setup_connector(self, response, cache=None, remaining_keys=None):
        cache = cache or {}
        remaining_keys = remaining_keys or set()
        counter = create_mock_full({"inc()": self.REQ_ID})
        connector = SCIONDConnector("addr", counter)
        connector._create_socket = create_mock()
        connector._get_response = create_mock_full(return_value=response)
        connector._try_cache = create_mock_full(return_value=(remaining_keys, cache))
        return connector


class TestSCIONDConnectorGetPaths(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_paths"""
    def _create_response(self, entries, with_error):
        p = create_mock_full(
            {"errorCode": PRE.NO_PATHS if with_error else PRE.OK})
        return create_mock_full({"p": p, "iter_entries()": entries})

    @patch("lib.app.sciond.SCIONDPathRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test(self, sciond_msg, path_req):
        connector = self._setup_connector(
            self._create_response(["1", "2"], False))
        flags = PathRequestFlags(flush=True, sibra=False)
        dst_src_maxpaths = (1, 2, 5)
        # Call
        paths = connector.get_paths(*dst_src_maxpaths, flags=flags)
        # Tests
        ntools.eq_(paths, ["1", "2"])
        sciond_msg.assert_called_once_with(path_req.return_value, self.REQ_ID)
        path_req.assert_called_once_with(*dst_src_maxpaths, flags.flush, flags.sibra)
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.PATH_REPLY)

    def test_with_error(self):
        connector = self._setup_connector(
            self._create_response([], True))
        # Call
        ntools.assert_raises(SCIONDResponseError, connector.get_paths, 1, 2, 5)


class TestSCIONDConnectorGetASInfo(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_as_info"""
    def _setup(self, cache=None):
        return self._setup_connector(
            create_mock_full({"iter_entries()": ["as_info"]}), cache)

    @patch("lib.app.sciond.SCIONDASInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_local(self, sciond_msg, as_info_req):
        connector = self._setup()
        # Call
        ntools.eq_(connector.get_as_info(), ["as_info"])
        # Tests
        ntools.eq_(connector._as_infos["local"], ["as_info"])
        connector._try_cache.assert_called_once_with(connector._as_infos, ["local"])
        sciond_msg.assert_called_once_with(as_info_req.return_value, self.REQ_ID)
        as_info_req.assert_called_once_with(None)
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.AS_REPLY)

    @patch("lib.app.sciond.SCIONDASInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_remote(self, sciond_msg, as_info_req):
        connector = self._setup()
        isd_as = ISD_AS("1-ff00:0:300")
        # Call
        ntools.eq_(connector.get_as_info(isd_as), ["as_info"])
        # Tests
        ntools.eq_(connector._as_infos[isd_as], ["as_info"])
        connector._try_cache.assert_called_once_with(connector._as_infos, [isd_as])
        as_info_req.assert_called_once_with(isd_as)
        sciond_msg.assert_called_once_with(as_info_req.return_value, self.REQ_ID)

    @patch("lib.app.sciond.SCIONDASInfoRequest.from_values", new_callable=create_mock)
    def test_with_cache(self, as_info_req):
        isd_as = ISD_AS("1-ff00:0:300")
        connector = self._setup({"local": ["as_info1"], isd_as: ["as_info2"]})
        # Call
        ntools.eq_(connector.get_as_info(), ["as_info1"])
        ntools.eq_(connector.get_as_info(isd_as), ["as_info2"])
        # Tests
        ntools.assert_false(as_info_req.called)
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

    @patch("lib.app.sciond.SCIONDIFInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_all(self, sciond_msg, if_info_req):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_if_info(), {1: entries[0], 2: entries[1]})
        # Tests
        ntools.eq_(connector._if_infos[1], entries[0])
        ntools.eq_(connector._if_infos[2], entries[1])
        ntools.assert_false(connector._try_cache.called)
        sciond_msg.assert_called_once_with(if_info_req.return_value, self.REQ_ID)
        if_info_req.assert_called_once_with(set())
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.IF_REPLY)

    @patch("lib.app.sciond.SCIONDIFInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_without_cache(self, sciond_msg, if_info_req):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": entries}), remaining_keys={1, 2})
        # Call
        ntools.eq_(connector.get_if_info([1, 2]), {1: entries[0], 2: entries[1]})
        # Tests
        connector._try_cache.assert_called_once_with(connector._if_infos, [1, 2])
        sciond_msg.assert_called_once_with(if_info_req.return_value, self.REQ_ID)
        if_info_req.assert_called_once_with({1, 2})

    @patch("lib.app.sciond.SCIONDIFInfoRequest.from_values", new_callable=create_mock)
    def test_get_with_cache(self, if_info_req):
        cache = {1: "if1", 2: "if2"}
        connector = self._setup_connector(response=None, cache=cache)
        # Call
        ntools.eq_(connector.get_if_info([1, 2]), {1: "if1", 2: "if2"})
        # Tests
        connector._try_cache.assert_called_once_with(connector._if_infos, [1, 2])
        ntools.assert_false(connector._create_socket.called)
        ntools.assert_false(connector._get_response.called)
        ntools.assert_false(if_info_req.called)

    @patch("lib.app.sciond.SCIONDIFInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_partial_cache(self, sciond_msg, if_info_req):
        cache = {1: "if1", 2: "if2"}
        response_entries = self._create_entries([(3, "if3")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": response_entries}),
            cache=cache, remaining_keys={3})
        # Call
        ntools.eq_(connector.get_if_info([1, 2, 3]),
                   {1: cache[1], 2: cache[2], 3: response_entries[0]})
        # Tests
        ntools.eq_(connector._if_infos[3], response_entries[0])
        connector._try_cache.assert_called_once_with(connector._if_infos, [1, 2, 3])
        sciond_msg.assert_called_once_with(if_info_req.return_value, self.REQ_ID)
        if_info_req.assert_called_once_with({3})

    @patch("lib.app.sciond.SCIONDIFInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_duplicates(self, sciond_msg, if_info_req):
        entries = self._create_entries([(1, "if1"), (2, "if2")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": entries}), remaining_keys={1, 2})
        # Call
        ntools.eq_(connector.get_if_info([1, 2, 2, 2]), {1: entries[0], 2: entries[1]})
        # Tests
        connector._try_cache.assert_called_once_with(connector._if_infos, [1, 2, 2, 2])
        sciond_msg.assert_called_once_with(if_info_req.return_value, self.REQ_ID)
        if_info_req.assert_called_once_with({1, 2})


class TestSCIONDConnectorGetServiceInfo(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_service_info"""
    def _create_entries(self, descs):
        response_entries = []
        for desc in descs:
            response_entries.append(create_mock_full(
                {"service_type()": desc[0], "host_info()": desc[1]}))
        return response_entries

    @patch("lib.app.sciond.SCIONDServiceInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_all(self, sciond_msg, svc_info_req):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(create_mock_full({"iter_entries()": entries}))
        # Call
        ntools.eq_(connector.get_service_info(), {"bs": entries[0], "ps": entries[1]})
        # Tests
        ntools.eq_(connector._svc_infos["bs"], entries[0])
        ntools.eq_(connector._svc_infos["ps"], entries[1])
        ntools.assert_false(connector._try_cache.called)
        sciond_msg.assert_called_once_with(svc_info_req.return_value, self.REQ_ID)
        svc_info_req.assert_called_once_with(set())
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SERVICE_REPLY)

    @patch("lib.app.sciond.SCIONDServiceInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_without_cache(self, sciond_msg, svc_info_req):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": entries}), remaining_keys={"bs", "ps"})
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps"]),
                   {"bs": entries[0], "ps": entries[1]})
        # Tests
        connector._try_cache.assert_called_once_with(connector._svc_infos, ["bs", "ps"])
        sciond_msg.assert_called_once_with(svc_info_req.return_value, self.REQ_ID)
        svc_info_req.assert_called_once_with({"bs", "ps"})

    @patch("lib.app.sciond.SCIONDServiceInfoRequest.from_values", new_callable=create_mock)
    def test_get_with_cache(self, svc_info_req):
        cache = {"bs": "bs1", "ps": "ps1"}
        connector = self._setup_connector(None, cache=cache)
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps"]), {"bs": "bs1", "ps": "ps1"})
        # Tests
        connector._try_cache.assert_called_once_with(connector._svc_infos, ["bs", "ps"])
        ntools.assert_false(svc_info_req.called)
        ntools.assert_false(connector._create_socket.called)
        ntools.assert_false(connector._get_response.called)

    @patch("lib.app.sciond.SCIONDServiceInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_partial_cache(self, sciond_msg, svc_info_req):
        cache = {"bs": "bs1", "ps": "ps1"}
        response_entries = self._create_entries([("cs", "cs1")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": response_entries}),
            cache=cache, remaining_keys={"cs"})
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps", "cs"]),
                   {"bs": cache["bs"], "ps": cache["ps"], "cs": response_entries[0]})
        # Tests
        ntools.eq_(connector._svc_infos["cs"], response_entries[0])
        connector._try_cache.assert_called_once_with(connector._svc_infos, ["bs", "ps", "cs"])
        sciond_msg.assert_called_once_with(svc_info_req.return_value, self.REQ_ID)
        svc_info_req.assert_called_once_with({"cs"})

    @patch("lib.app.sciond.SCIONDServiceInfoRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_get_duplicates(self, sciond_msg, svc_info_req):
        entries = self._create_entries([("bs", "bs1"), ("ps", "ps1")])
        connector = self._setup_connector(
            create_mock_full({"iter_entries()": entries}), remaining_keys={"bs", "ps"})
        # Call
        ntools.eq_(connector.get_service_info(["bs", "ps", "bs", "ps"]),
                   {"bs": entries[0], "ps": entries[1]})
        # Tests
        connector._try_cache.assert_called_once_with(connector._svc_infos, ["bs", "ps", "bs", "ps"])
        sciond_msg.assert_called_once_with(svc_info_req.return_value, self.REQ_ID)
        svc_info_req.assert_called_once_with({"bs", "ps"})


class TestSCIONDConnectorResolveDstAddr:
    """Unit tests for lib.app.sciond.SCIONDConnector._resolve_dst_addr"""
    def _setup_connector(self, svc_info_desc=None):
        counter = create_mock_full({"inc()": 1})
        connector = SCIONDConnector("addr", counter)
        if svc_info_desc:
            svc_info = create_mock_full({"host_info()": svc_info_desc[1]})
            connector.get_service_info = create_mock_full(
                return_value={svc_info_desc[0]: svc_info})
        else:
            connector.get_service_info = create_mock()
        return connector

    def test_with_svc(self):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:300"), SVCType.BS_A)
        src_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:300"), HostAddrIPv4("127.0.0.1"))
        connector = self._setup_connector(svc_info_desc=("bs", "bs1"))
        # Call
        ntools.eq_(connector._resolve_dst_addr(src_addr, dst_addr), "bs1")
        # Tests
        connector.get_service_info.assert_called_once_with(["bs"])

    @patch("lib.app.sciond.HostInfo.from_values", new_callable=create_mock)
    def test_with_host(self, host_info):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:300"), HostAddrIPv4("127.0.0.2"))
        src_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:300"), HostAddrIPv4("127.0.0.1"))
        connector = self._setup_connector()
        # Call
        ntools.eq_(connector._resolve_dst_addr(src_addr, dst_addr),
                   host_info.return_value)
        # Tests
        ntools.assert_false(connector.get_service_info.called)
        host_info.assert_called_once_with([HostAddrIPv4("127.0.0.2")], SCION_UDP_EH_DATA_PORT)

    def test_with_different_ases(self):
        dst_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:301"), HostAddrSVC(0, raw=False))
        src_addr = SCIONAddr.from_values(ISD_AS("1-ff00:0:300"), HostAddrIPv4("127.0.0.1"))
        connector = self._setup_connector(svc_info_desc=("bs", "bs1"))
        # Call
        ntools.eq_(connector._resolve_dst_addr(src_addr, dst_addr), None)
        # Tests
        ntools.assert_false(connector.get_service_info.called)


class TestSCIONDConnectorTryCache:
    """Unit tests for lib.app.sciond.SCIONDConnector._try_cache"""
    def test(self):
        cache = {1: "a", 2: "b", 3: "c"}
        key_list = [1, 2]
        # Call
        ntools.eq_(SCIONDConnector._try_cache(cache, key_list), (set(), {1: "a", 2: "b"}))

    def test_empty_cache(self):
        cache = {}
        key_list = [1, 2]
        # Call
        ntools.eq_(SCIONDConnector._try_cache(cache, key_list), ({1, 2}, {}))

    def test_empty_key_list(self):
        cache = {1: "a", 2: "b", 3: "c"}
        key_list = []
        # Call
        ntools.eq_(SCIONDConnector._try_cache(cache, key_list), (set(), {}))

    def test_partial_hit(self):
        cache = {1: "a", 3: "c"}
        key_list = [1, 2]
        # Call
        ntools.eq_(SCIONDConnector._try_cache(cache, key_list), ({2}, {1: "a"}))

    def test_duplicate_keys(self):
        cache = {1: "a", 2: "b", 3: "c"}
        key_list = [1, 2, 1, 2]
        # Call
        ntools.eq_(SCIONDConnector._try_cache(cache, key_list), (set(), {1: "a", 2: "b"}))


class TestSCIONDConnectorGetTypeSegs(SCIONDConnectorTestBase):
    """Unit tests for lib.app.sciond.SCIONDConnector.get_segtype_hops"""

    def _setup(self):
        return self._setup_connector(
            create_mock_full({"iter_entries()": ["segment"]}))

    @patch("lib.app.sciond.SCIONDSegTypeHopRequest.from_values", new_callable=create_mock)
    @patch("lib.app.sciond.SCIONDMsg", new_callable=create_mock)
    def test_valid_type(self, sciond_msg, segment_req):
        connector = self._setup()
        seg_type = PST.CORE
        # Call
        segments = connector.get_segtype_hops(seg_type)
        # Tests
        ntools.eq_(segments, ["segment"])
        sciond_msg.assert_called_once_with(segment_req.return_value, self.REQ_ID)
        segment_req.assert_called_once_with(seg_type)
        connector._create_socket.assert_called_once_with()
        connector._get_response.assert_called_once_with(ANY, 1, SMT.SEGTYPEHOP_REPLY)

    def test_invalid_type(self):
        connector = self._setup()
        seg_type = 'unset'
        # Call
        ntools.assert_raises(AssertionError, connector.get_segtype_hops, seg_type)
