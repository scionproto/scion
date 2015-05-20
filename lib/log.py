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
import traceback

# This file should not include other SCION libraries, to prevent cirular import
# errors.


class _StreamErrorHandler(logging.StreamHandler):
    """
    A logging StreamHandler that will exit the application if there's a logging
    exception.

    We don't try to use the normal logging system at this point because we
    don't know if that's working at all. If it is (e.g. when the exception is a
    formatting error), when we re-raise the exception, it'll get handled by the
    normal process.
    """
    def handleError(self, record):
        self.stream.write("Exception in logging module:\n")
        for line in traceback.format_exc().split("\n"):
            self.stream.write(line+"\n")
        self.flush()
        raise


def init_logging(level=logging.DEBUG):
    """
    Configure logging for components (servers, routers, gateways).
    """
    logging.basicConfig(level=level,
                        handlers=[_StreamErrorHandler()],
                        format='%(asctime)s [%(levelname)s]\t'
                               '(%(threadName)s) %(message)s')


def log_exception(msg, *args, level=logging.CRITICAL, **kwargs):
    """
    Properly format an exception before logging
    """
    logging.log(level, msg, *args, **kwargs)
    for line in traceback.format_exc().split("\n"):
        logging.log(level, line)
