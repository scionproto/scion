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
:mod:`thread` --- Thread handling
=================================

Threading utilities for SCION.
"""
# Stdlib
import os
import signal
import threading

# SCION
from lib.log import log_exception


def kill_self():  # pragma: no cover
    """
    Send SIGINT to self, to allow quitting the process from threads when fatal
    errors occur.
    """
    os.kill(os.getpid(), signal.SIGUSR2)
    signal.pause()


def thread_safety_net(func, *args, **kwargs):
    """
    Wrapper function to handle uncaught thread exceptions, log them, then kill
    the process.

    :type name: string
    :param func: function to call
    :type func: function
    """
    name = threading.current_thread().name
    try:
        return func(*args, **kwargs)
    except:
        log_exception("Exception in %s thread:", name)
        kill_self()
