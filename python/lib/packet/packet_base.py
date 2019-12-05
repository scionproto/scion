# Copyright 2014 ETH Zurich
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
:mod:`packet_base` --- Packet base class
========================================
"""
# Stdlib
from abc import ABCMeta, abstractmethod


class Serializable(object, metaclass=ABCMeta):  # pragma: no cover
    """
    Base class for all objects which serialize into raw bytes.
    """
    def __init__(self, raw=None):
        if raw:
            self._parse(raw)

    @abstractmethod
    def _parse(self, raw):
        raise NotImplementedError

    @abstractmethod
    def from_values(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        raise NotImplementedError

    @abstractmethod
    def __len__(self):
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError
