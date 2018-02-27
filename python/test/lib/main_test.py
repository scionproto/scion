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
:mod:`lib_main_test` --- lib.main unit tests
============================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.main import main_default, main_wrapper
from test.testcommon import create_mock


class TestMainWrapper(object):
    """
    Unit tests for lib.main.main_wrapper
    """
    def test_basic(self):
        main = create_mock()
        # Call
        main_wrapper(main, "arg1", arg2="arg2")
        # Tests
        main.assert_called_once_with("arg1", arg2="arg2")

    def test_sysexit(self):
        main = create_mock()
        main.side_effect = SystemExit
        # Call
        ntools.assert_raises(SystemExit, main_wrapper, main)

    @patch("lib.main.sys.exit", autospec=True)
    @patch("lib.main.log_exception", autospec=True)
    def test_excp(self, log_excp, exit):
        main = create_mock()
        main.side_effect = KeyError
        # Call
        main_wrapper(main)
        # Tests
        ntools.ok_(log_excp.called)
        ntools.ok_(exit.called)


class TestMainDefault(object):
    """
    Unit tests for lib.main.main_default
    """
    @patch("lib.main.trace", autospec=True)
    @patch("lib.main.init_logging", autospec=True)
    @patch("lib.main.argparse.ArgumentParser", autospec=True)
    @patch("lib.main.handle_signals", autospec=True)
    def test_trace(self, signals, argparse, init_log, trace):
        type_ = create_mock()
        inst = type_.return_value = create_mock(["id", "run"])
        parser = argparse.return_value
        args = parser.parse_args.return_value
        args.log_dir = "logging"
        args.server_id = "srvid"
        args.conf_dir = "confdir"
        args.prom = "prom"
        args.spki_cache_dir = "gen-cache"
        # Call
        main_default(type_, trace_=True, kwarg1="kwarg1")
        # Tests
        signals.assert_called_once_with()
        argparse.assert_called_once_with()
        ntools.ok_(parser.add_argument.called)
        parser.parse_args.assert_called_once_with()
        init_log.assert_called_once_with("logging/srvid")
        type_.assert_called_once_with("srvid", "confdir", spki_cache_dir="gen-cache",
                                      prom_export="prom", kwarg1="kwarg1")
        trace.assert_called_once_with(inst.id)
        inst.run.assert_called_once_with()

    @patch("lib.main.Topology.from_file", new_callable=create_mock)
    @patch("lib.main.init_logging", autospec=True)
    @patch("lib.main.argparse.ArgumentParser", autospec=True)
    @patch("lib.main.handle_signals", autospec=True)
    def _check_core_local(self, is_core, core_called, local_called, signals,
                          argparse, init_log, topo):
        core_type = create_mock()
        local_type = create_mock()
        topo.return_value = create_mock(["is_core_as"])
        topo.return_value.is_core_as = is_core
        # Call
        main_default(core_type, local_type)
        # Tests
        ntools.eq_(core_type.called, core_called)
        ntools.eq_(local_type.called, local_called)

    def test_core_local(self):
        yield self._check_core_local, True, True, False
        yield self._check_core_local, False, False, True

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
