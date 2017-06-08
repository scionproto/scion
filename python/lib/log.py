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
LOG_MAX_SIZE = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 1

# Logging handlers that will log logging exceptions, and then re-raise them. The
# default behaviour of python's logging handlers is to catch logging exceptions,
# which hides the problem.
#
# We don't try to use the normal logging system at this point because we don't
# know if that's working at all. If it is (e.g. when the exception is a
# formatting error), when we re-raise the exception, it'll get handled by the
# normal process.

_dispatch_formatter = None


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


class Rfc3339Formatter(logging.Formatter):
    def format(self, record):  # pragma: no cover
        lines = super().format(record).splitlines()
        return "\n> ".join(lines)

    def formatTime(self, record, _):  # pragma: no cover
        # Not using lib.util.iso_timestamp here, to avoid potential import
        # loops.
        # Also, using str on a datetime object inserts a ":" into the time zone,
        # which, while legal, is inconsistent with logging in Go and Zlog. Fortunately,
        # Python's strftime does the right thing.
        return datetime.fromtimestamp(
            record.created, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f%z")


class DispatchFormatter:  # pragma: no cover
    """
    A dispatching formatter that allows modules to install custom formatters for
    their child loggers.
    """
    def __init__(self, default_formatter, formatters=None):
        self._default_formatter = default_formatter
        self._formatters = formatters or {}

    def add_formatter(self, key, formatter):
        self._formatters[key] = formatter

    def format(self, record):
        formatter = self._formatters.get(record.name, self._default_formatter)
        return formatter.format(record)


def add_formatter(name, formatter):  # pragma: no cover
    _dispatch_formatter.add_formatter(name, formatter)


def init_logging(log_base=None, file_level=logging.DEBUG,
                 console_level=logging.NOTSET):
    """
    Configure logging for components (servers, routers, gateways).
    """
    default_formatter = Rfc3339Formatter(
        "%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s")
    global _dispatch_formatter
    _dispatch_formatter = DispatchFormatter(default_formatter)
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
        h.setFormatter(_dispatch_formatter)
    # Use logging.DEBUG here, so that the handlers themselves can decide what to
    # filter.
    logging.basicConfig(level=logging.DEBUG, handlers=handlers)


def log_exception(msg, *args, level=logging.CRITICAL, **kwargs):
    """
    Properly format an exception before logging.
    """
    logging.log(level, msg, *args, **kwargs)
    for line in traceback.format_exc().split("\n"):
        logging.log(level, line)


def log_stack(level=logging.DEBUG):
    logging.log(level, "".join(traceback.format_stack()))
