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

# SCION
from python.lib.errors import SCIONParseError


class ISD_AS:
    """
    Class for representing ISD-AS pair. The underlying type is a 64-bit unsigned int; ISD is
    represented by the top 16 bits (though the top 4 bits are currently reserved), and AS by the
    lower 48 bits.
    See formatting and allocations here:
    https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering
    """
    ISD_BITS = 16
    MAX_ISD = (1 << ISD_BITS) - 1
    AS_BITS = 48
    MAX_AS = (1 << AS_BITS) - 1
    BGP_AS_BITS = 32
    MAX_BGP_AS = (1 << BGP_AS_BITS) - 1
    HEX_AS_PARTS = 3  # E.g. ff00:0:abcd
    HEX_SEPARATOR = ":"
    HEX_FILE_SEPARATOR = "_"
    MAX_HEX_AS_PART = 0xffff

    def __init__(self, raw=None):
        self._isd = 0
        self._as = 0
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        :param str raw: a string of the format "isd-as".
        """
        parts = raw.split("-")
        if len(parts) != 2:
            raise SCIONParseError("Unable to split ISD-AS in string: %s" % raw)
        isd_s, as_s = parts
        self._parse_isd_str(isd_s)
        for as_sep in [self.HEX_SEPARATOR, self.HEX_FILE_SEPARATOR]:
            if as_sep in as_s:
                self._parse_hex_as(as_s, as_sep)
                break
        else:
            self._parse_dec_as(as_s)

    def _parse_isd_str(self, raw):
        try:
            self._isd = int(raw)
        except ValueError:
            raise SCIONParseError("Unable to parse ISD from string: %s" % raw) from None
        if self._isd > self.MAX_ISD:
            raise SCIONParseError("ISD too large (max: %d): %s" % (self.MAX_ISD, raw))

    def _parse_dec_as(self, raw):
        try:
            self._as = int(raw, base=10)
        except ValueError:
            raise SCIONParseError("Unable to parse decimal AS from string: %s" % raw) from None
        if self._as > self.MAX_BGP_AS:
            raise SCIONParseError("Decimal AS too large (max: %d): %s" % (self.MAX_BGP_AS, raw))

    def _parse_hex_as(self, raw, as_sep=HEX_SEPARATOR):
        try:
            as_parts = raw.split(as_sep)
        except ValueError:
            raise SCIONParseError("Unable to parse hex AS from string: %s" % raw) from None
        if len(as_parts) != self.HEX_AS_PARTS:
            raise SCIONParseError(
                "Wrong number of separators (%s) in hex AS number (expected: %d actual: %s): %s" %
                (self.HEX_SEPARATOR, self.HEX_AS_PARTS,  as_parts, raw))
        self._as = 0
        for i, s in enumerate(as_parts):
            self._as <<= 16
            v = int(s, base=16)
            if v > self.MAX_HEX_AS_PART:
                raise SCIONParseError("Hex AS number has part greater than %x: %s" %
                                      (self.MAX_HEX_AS_PART, raw))
            self._as |= v
        if self._as > self.MAX_AS:
            raise SCIONParseError("AS too large (max: %d): %s" % (self.MAX_AS, raw))

    def _parse_int(self, raw):
        """
        :param int raw: a 64-bit unsigned integer
        """
        self._isd = raw >> self.AS_BITS
        self._as = raw & self.MAX_AS

    def int(self):
        isd_as = self._isd << self.AS_BITS
        isd_as |= self._as & self.MAX_AS
        return isd_as

    def any_as(self):  # pragma: no cover
        return self.from_values(self._isd, 0)

    def is_zero(self):  # pragma: no cover
        return self._isd == 0 and self._as == 0

    def __eq__(self, other):  # pragma: no cover
        return self._isd == other._isd and self._as == other._as

    def isd_str(self):
        s = str(self._isd)
        if self._isd > self.MAX_ISD:
            return "%s [Illegal ISD: larger than %d]" % (s, self.MAX_ISD)
        return s

    def as_str(self, sep=HEX_SEPARATOR):
        dec_str = str(self._as)
        if self._as > self.MAX_AS:
            return "%s [Illegal AS: larger than %d]" % (dec_str, self.MAX_AS)
        if self._as <= self.MAX_BGP_AS:
            return str(self._as)
        s = []
        as_ = self._as
        for i in range(self.HEX_AS_PARTS):
            s.insert(0, "%x" % (as_ & self.MAX_HEX_AS_PART))
            as_ >>= 16
        return sep.join(s)

    def as_file_fmt(self):
        return self.as_str(self.HEX_FILE_SEPARATOR)

    def file_fmt(self):
        return "%s-%s" % (self.isd_str(), self.as_file_fmt())

    def __str__(self, as_sep=HEX_SEPARATOR):
        return "%s-%s" % (self.isd_str(), self.as_str(as_sep))

    def __repr__(self):  # pragma: no cover
        return "ISD_AS(isd=%s, as=%s)" % (self._isd, self._as)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __hash__(self):  # pragma: no cover
        return hash(str(self))

    @classmethod
    def parse_int(cls, raw: int):
        ia = ISD_AS()
        ia._parse_int(raw)
        return ia
