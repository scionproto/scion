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
:mod:`scion_addr` --- SCION host address specifications
=======================================================
"""

import re


class ISD_AS:
    """
    Class for representing ISD-AS pair.
    """

    def __init__(self, isd_as_str):
        isd_as_str = _clean_isd_as(isd_as_str)
        self._isd, self._as = isd_as_str.split("-")

    def isd_str(self):
        return self._isd

    def as_str(self):
        return self._as

    def as_file_fmt(self):
        return self._as.replace(":", "_")

    def file_fmt(self):
        return "%s-%s" % (self.isd_str(), self.as_file_fmt())

    def __str__(self):
        return "%s-%s" % (self.isd_str(), self.as_str())

    def __repr__(self):
        return "<ISD_AS: %s>" % self

    def __eq__(self, other):
        if not isinstance(other, ISD_AS):
            return False
        return self._isd == other._isd and self._as == other._as

    def __hash__(self):
        return hash(str(self))


# Regex matching ISD-AS (hex or decimal form), with either : or _ as hex-part separator
_RE_ISD_AS = re.compile(
    r"^([1-9][0-9]{0,4})-([0-9a-fA-F]{1,4})[:_]([0-9a-fA-F]{1,4})[:_]([0-9a-fA-F]{1,4})" +
    r"|([1-9][0-9]{0,4})-([1-9][0-9]{1,9})$"
)


def _clean_isd_as(isd_as_str):
    """
    Parse an ISD-AS-identifier and return the "canonical" string representation.

    :param str as_id_str: AS-identifier to parse
    :returns: AS-identifier as integer
    :raises:
        ValueError: invalid ISD-AS
    """
    m = _RE_ISD_AS.match(isd_as_str)
    if not m:
        raise ValueError('Invalid ISD-AS', isd_as_str)
    if m.group(1) is not None:
        isd = int(m.group(1), 10)
        hig = int(m.group(2), 16)
        mid = int(m.group(3), 16)
        low = int(m.group(4), 16)
        asn = (hig << 32) | (mid << 16) | low
    else:
        isd = int(m.group(5), 10)
        asn = int(m.group(6), 10)
        if asn >= 2**32:
            ValueError('Invalid ISD-AS, ASN out of range', isd_as_str)
    if isd >= 2**16:
        raise ValueError('Invalid ISD-AS, ISD out of range', isd_as_str)
    if asn < 2**32:
        return "%i-%d" % (isd, asn)
    else:
        return "%i-%x:%x:%x" % (isd, hig, mid, low)
