# Copyright 2016 ETH Zurich
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
:mod:`dispatcher` --- Dispatcher utilities
==========================================

Helper functions for dealing with dispatcher.
"""

# Stdlib
import logging
import os
import struct
import time

# SCION
from lib.defines import (
    DEFAULT_DISPATCHER_ID,
    DISPATCHER_DIR,
    DISPATCHER_TIMEOUT,
)
from lib.thread import kill_self
from lib.types import L4Proto


def reg_dispatcher(sock, addr, port, bind=(), init=True, svc=None, scmp=True):
    """
    Helper function for registering app with dispatcher
    """
    bind_addr, bind_port = None, None
    if bind:
        bind_addr, bind_port = bind
    buf = _pack_dispatcher_msg(addr, port, bind_addr, bind_port, svc, scmp)
    if not _connect_dispatcher(sock, init):
        return
    try:
        sock.send(buf)
    except OSError:
        logging.error("Error while sending registration message")
        return False
    old_timeout = sock.settimeout(30.0)
    try:
        buf, _ = sock.recv()
    except OSError:
        logging.error("Error while receiving registration response")
        return False
    if not buf:
        logging.error("Dispatcher closed socket, retry later")
        return False
    port = struct.unpack("!H", buf)[0]
    if not port:
        logging.critical("Failed to register with dispatcher")
        kill_self()
    logging.debug("Registered to dispatcher for addr %s:%d", addr, port)
    sock.port = port
    sock.settimeout(old_timeout)
    return True


def _pack_dispatcher_msg(addr, port, bind_addr, bind_port, svc, scmp):
    cmd = 1
    if scmp:
        cmd |= 1 << 1
    data = []
    if bind_addr:
        cmd |= 1 << 2
    data.append(struct.pack("!BBQHB", cmd, L4Proto.UDP, addr.isd_as.int(), port, addr.host.TYPE))
    data.append(addr.host.pack())
    if bind_addr:
        data.append(struct.pack("!HB", bind_port, bind_addr.host.TYPE))
        data.append(bind_addr.host.pack())
    if svc is not None:
        data.append(svc.pack())
    return b"".join(data)


def _connect_dispatcher(sock, init):
    start = time.time()
    now = start
    dispatcher_id = os.getenv("DISPATCHER_ID") or DEFAULT_DISPATCHER_ID
    path = os.path.join(DISPATCHER_DIR, dispatcher_id + ".sock")
    logging.debug("connect to dispatcher at path %s", path)
    while True:
        try:
            logging.debug("Attempt connect")
            sock.connect(path)
            break
        except OSError as e:
            logging.warning("Connect error: %s", e)
            return False
        if not init:
            logging.warning("Dispatcher unavailable, retry later")
            return False
        time.sleep(1)
        now = time.time()
        if now > start + DISPATCHER_TIMEOUT:
            logging.critical("Dispatcher unreachable for too long, abort")
            return False
    return True
