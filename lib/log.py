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
:mod:`log` --- Logging utilites
===============================
"""
# Stdlib
import logging
import logging.handlers
import traceback
from datetime import datetime, timezone

# This file should not include other SCION libraries, to prevent circular import
# errors.

#: Bytes
LOG_MAX_SIZE = 1 * 1024 * 1024
LOG_BACKUP_COUNT = 1

# Logging handlers that will log logging exceptions, and then re-raise them. The
# default behaviour of python's logging handlers is to catch logging exceptions,
# which hides the problem.
#
# We don't try to use the normal logging system at this point because we don't
# know if that's working at all. If it is (e.g. when the exception is a
# formatting error), when we re-raise the exception, it'll get handled by the
# normal process.


def _handleError(self, _):
    self.stream.write("Exception in logging module:\n")
    for line in traceback.format_exc().split("\n"):
        self.stream.write(line+"\n")
    self.flush()
    raise


class _RotatingErrorHandler(logging.handlers.RotatingFileHandler):
    handleError = _handleError


class _ConsoleErrorHandler(logging.StreamHandler):
    handleError = _handleError


class _Rfc3339Formatter(logging.Formatter):
    def formatTime(self, record, _):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(' ')


def init_logging(log_base=None, file_level=logging.DEBUG,
                 console_level=logging.NOTSET):
    """
    Configure logging for components (servers, routers, gateways).
    """
    formatter = _Rfc3339Formatter(
        "%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s")
    handlers = []
    if log_base:
        for lvl in sorted(logging._levelToName):
            if lvl < file_level:
                continue
            log_file = "%s.%s" % (log_base, logging._levelToName[lvl])
            h = _RotatingErrorHandler(
                log_file, maxBytes=LOG_MAX_SIZE, backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8")
            h.setLevel(lvl)
            handlers.append(h)
    if console_level:
        h = _ConsoleErrorHandler()
        h.setLevel(console_level)
        handlers.append(h)
    for h in handlers:
        h.setFormatter(formatter)
    # Use logging.DEBUG here, so that the handlers themselves can decide what to
    # filter.
    logging.basicConfig(level=logging.DEBUG, handlers=handlers)


def log_exception(msg, *args, level=logging.CRITICAL, **kwargs):
    """
    Properly format an exception before logging.

    :param msg:
    :type msg:
    :param args:
    :type args:
    :param level:
    :type level:
    :param kwargs:
    :type kwargs:
    """
    logging.log(level, msg, *args, **kwargs)
    for line in traceback.format_exc().split("\n"):
        logging.log(level, line)
