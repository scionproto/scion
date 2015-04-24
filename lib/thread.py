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

import os
import signal
from functools import wraps

from lib.log import log_exception

def kill_self():
    """
    Sends SIGTERM to self, to allow quitting the process from threads.
    """
    os.kill(os.getpid(), signal.SIGTERM)

def thread_safety_net(name):
    """
    Decorator to handle uncaught thread exceptions, log them, then kill the
    process.
    """
    def wrap(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except:
                log_exception("Exception in %s thread:", name)
                kill_self()
        return wrapper
    return wrap
