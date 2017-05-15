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
:mod:`lib_log_test` --- lib.log unit tests
==========================================
"""
# Stdlib
import logging
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.log import (
    LOG_BACKUP_COUNT,
    LOG_MAX_SIZE,
    _handleError,
    init_logging,
    log_exception,
)
from test.testcommon import SCIONTestError, assert_these_calls, create_mock


class TestHandleError(object):
    """
    Unit tests for lib.log._handleError
    """
    @patch("lib.log.traceback.format_exc", autospec=True)
    def test(self, format_exc):
        # Setup
        handler = MagicMock(spec_set=["stream", "flush"])
        handler.stream = MagicMock(spec_set=['write'])
        handler.stream.write = MagicMock(spec_set=[])
        handler.flush = MagicMock(spec_set=[])
        format_exc.return_value = MagicMock(spec_set=['split'])
        format_exc.return_value.split.return_value = ['line0', 'line1']
        # Call
        try:
            raise SCIONTestError
        except:
            ntools.assert_raises(SCIONTestError, _handleError, handler, "hi")
        # Tests
        ntools.eq_(handler.stream.write.call_count, 3)
        handler.flush.assert_called_once_with()


class TestInitLogging(object):
    """
    Unit tests for lib.log.init_logging
    """
    @patch("lib.log.logging.basicConfig", autospec=True)
    @patch("lib.log._ConsoleErrorHandler", autospec=True)
    @patch("lib.log._RotatingErrorHandler", autospec=True)
    @patch("lib.log.DispatchFormatter", autospec=True)
    def test_full(self, formatter, rotate, console, basic_config):
        levels = "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
        file_handlers = [
            create_mock(["setLevel", "setFormatter"]),
            create_mock(["setLevel", "setFormatter"]),
            create_mock(["setLevel", "setFormatter"]),
            create_mock(["setLevel", "setFormatter"]),
            create_mock(["setLevel", "setFormatter"]),
        ]
        console_handler = console.return_value
        rotate.side_effect = file_handlers
        # Call
        init_logging("logbase", file_level=logging.DEBUG,
                     console_level=logging.CRITICAL)
        # Tests
        rotate_calls = []
        for lvl in levels:
            rotate_calls.append(call(
                "logbase.%s" % lvl, maxBytes=LOG_MAX_SIZE,
                backupCount=LOG_BACKUP_COUNT, encoding="utf-8"))
        assert_these_calls(rotate, rotate_calls)
        for lvl, f_h in zip(levels, file_handlers):
            f_h.setLevel.assert_called_once_with(logging._nameToLevel[lvl])
            f_h.setFormatter.assert_called_once_with(formatter.return_value)
        console_handler.setLevel.assert_called_once_with(logging.CRITICAL)
        console_handler.setFormatter.assert_called_once_with(
            formatter.return_value)
        basic_config.assert_called_once_with(
            level=logging.DEBUG, handlers=file_handlers + [console_handler]
        )

    @patch("lib.log._RotatingErrorHandler", autospec=True)
    @patch("lib.log.logging.basicConfig", autospec=True)
    def test_file(self, basic_config, rotate):
        # Call
        init_logging("logfile", file_level=logging.CRITICAL)
        # Tests
        basic_config.assert_called_once_with(
            level=logging.DEBUG, handlers=[rotate.return_value],
        )

    @patch("lib.log._ConsoleErrorHandler", autospec=True)
    @patch("lib.log.logging.basicConfig", autospec=True)
    def test_console(self, basic_config, console):
        # Call
        init_logging(console_level=logging.DEBUG)
        # Tests
        basic_config.assert_called_once_with(
            level=logging.DEBUG, handlers=[console.return_value],
        )


class TestLogException(object):
    """
    Unit tests for lib.log.log_exception
    """
    @patch("lib.log.traceback.format_exc", autospec=True)
    @patch("lib.log.logging.log", autospec=True)
    def test(self, log, format_exc):
        format_exc.return_value = MagicMock(spec_set=['split'])
        format_exc.return_value.split.return_value = ['line0', 'line1']
        log_exception('msg', 'arg0', level=123, arg1='arg1')
        log.assert_has_calls([call(123, 'msg', 'arg0', arg1='arg1'),
                              call(123, 'line0'), call(123, 'line1')])

    @patch("lib.log.traceback.format_exc", autospec=True)
    @patch("lib.log.logging.log", autospec=True)
    def test_less_arg(self, log, format_exc):
        format_exc.return_value = MagicMock(spec_set=['split'])
        format_exc.return_value.split.return_value = ['line0', 'line1']
        log_exception('msg', 'arg0', arg1='arg1')
        calls = [call(logging.CRITICAL, 'msg', 'arg0', arg1='arg1'),
                 call(logging.CRITICAL, 'line0'),
                 call(logging.CRITICAL, 'line1')]
        log.assert_has_calls(calls)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
