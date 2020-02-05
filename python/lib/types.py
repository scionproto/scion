# Copyright 2015 ETH Zurich
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
:mod:`types` --- SCION types
============================

For all type classes that are used in multiple parts of the infrastructure.
"""


class TypeBase(object):  # pragma: no cover
    @classmethod
    def to_str(cls, type_, error=False):
        for attr in dir(cls):
            if getattr(cls, attr) == type_:
                return attr
        if not error:
            return "UNKNOWN (%s)" % type_
        raise IndexError

    @classmethod
    def all(cls):
        return [getattr(cls, attr) for attr in dir(cls) if
                not attr.startswith("__") and
                not callable(getattr(cls, attr))]


############################
# Basic types
############################
class AddrType(TypeBase):
    NONE = 0
    IPV4 = 1
    IPV6 = 2
    SVC = 3


############################
# Service types
############################
class ServiceType(TypeBase):
    # these values must be kept in sync with the common.capnp ServiceType enum
    #: Unset
    UNSET = "unset"
    #: Certificate service
    CS = "cs"
    #: Border router
    BR = "br"
    #: SCION-IP gateway
    SIG = "sig"


############################
# Link types
############################
class LinkType(TypeBase):
    # XXX(worxli): these values must be kept in sync with the capnp Linktype enum
    UNSET = "unset"
    #: Link to child AS
    CHILD = "child"
    #: Link to parent AS
    PARENT = "parent"
    #: Link to peer AS
    PEER = "peer"
    #: Link to other core AS
    CORE = "core"
