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
    _LoggingErrorHandler,
    init_logging,
    log_exception,
)
from test.testcommon import SCIONTestError


class TestLoggingErrorHandlerHandleError(object):
    """
    Unit tests for lib.log._LoggingErrorHandler.handleError
    """
    @patch("lib.log.traceback.format_exc", autospec=True)
    @patch("lib.log._LoggingErrorHandler.__init__", autospec=True)
    def test(self, init, format_exc):
        init.return_value = None
        handler = _LoggingErrorHandler("logfile")
        handler.stream = MagicMock(spec_set=['write'])
        handler.stream.write = MagicMock(spec_set=[])
        handler.flush = MagicMock(spec_set=[])
        format_exc.return_value = MagicMock(spec_set=['split'])
        format_exc.return_value.split.return_value = ['line0', 'line1']
        try:
            raise SCIONTestError
        except:
            ntools.assert_raises(SCIONTestError, handler.handleError, "hi")
        ntools.eq_(handler.stream.write.call_count, 3)
        handler.flush.assert_called_once_with()


class TestInitLogging(object):
    """
    Unit tests for lib.log.init_logging
    """
    @patch("lib.log._LoggingErrorHandler", autospec=True)
    @patch("lib.log.logging.basicConfig", autospec=True)
    def test(self, basic_config, handler):
        init_logging("logfile", 123)
        handler.assert_called_once_with(
            "logfile", maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8")
        basic_config.assert_called_once_with(
            level=123, handlers=[handler.return_value],
            format='%(asctime)s [%(levelname)s] '
                   '(%(threadName)s) %(message)s'
        )

    @patch("lib.log._LoggingErrorHandler", autospec=True)
    @patch("lib.log.logging.basicConfig", autospec=True)
    def test_less_arg(self, basic_config, handler):
        init_logging("logfile")
        basic_config.assert_called_once_with(
            level=logging.DEBUG, handlers=[handler.return_value],
            format='%(asctime)s [%(levelname)s] '
                   '(%(threadName)s) %(message)s'
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
