#!/usr/bin/env python3
#
# Copyright 2026 SCION Association
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

"""Slot pool manager for parallel acceptance test isolation.

Each slot provides a unique Docker Compose project name, network prefix,
IPv4 subnet, and artifacts directory. Slots are acquired via filesystem
locks and released on teardown or process exit.
"""

import fcntl
import logging
import os

logger = logging.getLogger(__name__)

NUM_SLOTS = 16
LOCK_DIR = "/tmp"
LOCK_PREFIX = "scion-test-slot-"


class Slot:
    """Represents an acquired test slot with derived resource names."""

    def __init__(self, slot_id: int, lock_fd: int):
        self.id = slot_id
        self._lock_fd = lock_fd

    @property
    def project_name(self) -> str:
        return "scion%d" % self.id

    @property
    def network(self) -> str:
        return "172.20.%d.0/20" % (self.id * 16)

    @property
    def artifacts_dir(self) -> str:
        return "/tmp/artifacts-scion-%d" % self.id

    def release(self):
        """Release the slot by closing the lock file descriptor."""
        if self._lock_fd is not None:
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
            logger.info("Released slot %d", self.id)


def acquire() -> Slot:
    """Acquire a free slot from the pool.

    Tries each slot in order, using flock(LOCK_EX | LOCK_NB) to acquire
    without blocking. Writes the current PID to the lock file for stale
    detection.

    If all slots are taken, checks for stale locks (dead PIDs) and reclaims
    the first one found.

    Returns:
        A Slot object with the acquired slot ID.

    Raises:
        RuntimeError: If no slot could be acquired (all 16 in use by live
            processes).
    """
    # First pass: try to acquire a free slot.
    for slot_id in range(NUM_SLOTS):
        fd = _try_acquire(slot_id)
        if fd is not None:
            return Slot(slot_id, fd)

    # Second pass: reclaim stale locks.
    for slot_id in range(NUM_SLOTS):
        lock_path = _lock_path(slot_id)
        try:
            with open(lock_path, "r") as f:
                pid = int(f.read().strip())
            # Check if the process is still alive.
            os.kill(pid, 0)
        except (OSError, ValueError):
            # Process is dead or PID is invalid. Reclaim.
            logger.warning("Reclaiming stale slot %d", slot_id)
            try:
                os.unlink(lock_path)
            except OSError:
                pass
            fd = _try_acquire(slot_id)
            if fd is not None:
                return Slot(slot_id, fd)

    raise RuntimeError(
        "No test slots available (all %d in use by live processes)" % NUM_SLOTS
    )


def _try_acquire(slot_id: int):
    """Try to acquire a slot by locking its file.

    Returns:
        The file descriptor if successful, None otherwise.
    """
    lock_path = _lock_path(slot_id)
    fd = -1
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Write our PID for stale detection.
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, ("%d\n" % os.getpid()).encode())
        logger.info("Acquired slot %d", slot_id)
        return fd
    except (OSError, IOError):
        # Could not lock - slot is taken.
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        return None


def _lock_path(slot_id: int) -> str:
    return os.path.join(LOCK_DIR, "%s%d.lock" % (LOCK_PREFIX, slot_id))
