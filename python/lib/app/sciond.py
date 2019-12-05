#!/usr/bin/python3
# Copyright 2017 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`sciond` --- Wrapper over low level SCIOND API
===================================================
"""
# Stdlib
import os

# SCION
from lib.defines import (
    SCIOND_API_DEFAULT_SOCK,
    SCIOND_API_SOCKDIR,
)


def get_default_sciond_path(ia=None):
    """Return sciond socket path for a given IA
    :param ia: ISD_AS addr
    :returns: Format string representing path of sciond socket
    """
    sock_path = ""
    if ia is None or ia.is_zero():
        sock_path = SCIOND_API_DEFAULT_SOCK
    else:
        sock_path = "sd%s.sock" % (ia.file_fmt())
    return os.path.join(SCIOND_API_SOCKDIR, sock_path)
