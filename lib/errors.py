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
:mod:`errors` --- SCION Errors
==============================
"""


class SCIONBaseException(Exception):
    """
    Root SCION Exception. All other exceptions derive from this.

    It should probably not be raised directly.
    """


class SCIONBaseError(SCIONBaseException):
    """
    Root SCION Error exception. All other error exceptions derive from this.

    It should probably not be raised directly.
    """
    pass


class SCIONIOError(SCIONBaseError):
    """
    IO error.
    """
    pass


class SCIONIndexError(SCIONBaseError):
    """
    Index error (accessing out of bound index on array)
    """
    pass


class SCIONKeyError(SCIONBaseError):
    """
    Key error (trying to access invalid entry in dictionary)
    """
    pass


class SCIONJSONError(SCIONBaseError):
    """
    JSON parsing error.
    """
    pass


class SCIONYAMLError(SCIONBaseError):
    """
    YAML parsing error.
    """
    pass


class SCIONParseError(SCIONBaseError):
    """
    Parsing error.
    """
    pass


class SCIONTypeError(SCIONBaseError):
    """
    Wrong type.
    """
    pass


class SCIONServiceLookupError(SCIONBaseError):
    """
    Service lookup failed.
    """
    pass
