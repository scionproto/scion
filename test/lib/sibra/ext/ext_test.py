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
:mod:`ext_test` --- lib.sibra.ext.ext unit tests
================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.sibra.ext.ext import (
    SibraExtBase,
)
from test.testcommon import create_mock

FLAG_MAP = (
    # Steady setup accepted fwd
    (0b11101100, (True, True, True, False, True, True, 0), True),
    # Ephemeral setup denied rev
    (0b11000000, (True, True, False, False, False, False, 0), False),
    # Steady use error fwd
    (0b00111100, (False, False, True, True, True, True, 0), True),
)


class SibraExtBaseTesting(SibraExtBase):
    NAME = "SibraExtBaseTesting"
    STEADY = None

    def from_values(self):
        pass

    def pack(self):
        pass


class TestSibraExtBaseParseStart(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_start
    """
    @patch("lib.sibra.ext.ext.HopByHopExtension._parse", autospec=True)
    @patch("lib.sibra.ext.ext.Raw", autospec=True)
    def test(self, raw, super_parse):
        inst = SibraExtBaseTesting()
        inst._parse_flags = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = "flags", "curr hop", bytes([4, 5, 0])
        raw.return_value = data
        # Call
        inst._parse_start("data")
        # Tests
        super_parse.assert_called_once_with(inst, "data")
        raw.assert_called_once_with("data", "SibraExtBaseTesting",
                                    inst.MIN_LEN, min_=True)
        inst._parse_flags.assert_called_once_with("flags")
        ntools.eq_(inst.curr_hop, "curr hop")
        ntools.eq_(inst.path_lens, (4, 5, 0))
        ntools.eq_(inst.total_hops, 9)


class TestSibraExtBaseParseEnd(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_end
    """
    def _setup(self, accepted=True):
        inst = SibraExtBaseTesting()
        inst.accepted = accepted
        inst._parse_block = create_mock()
        inst._parse_offers_block = create_mock()
        inst.total_hops = "total hops"
        inst.steady = "so steady"
        data = create_mock(["__len__"])
        data.__len__.return_value = 0
        return inst, data

    def test_req_accepted(self):
        inst, data = self._setup()
        # Call
        inst._parse_end(data, True)
        # Tests
        inst._parse_block.assert_called_once_with(
            data, "total hops", "so steady")
        ntools.eq_(inst.req_block, inst._parse_block.return_value)

    def test_req_rejected(self):
        inst, data = self._setup(accepted=False)
        # Call
        inst._parse_end(data, True)
        # Tests
        inst._parse_offers_block.assert_called_once_with(data)
        ntools.eq_(inst.req_block, inst._parse_offers_block.return_value)

    def test_data_remaining(self):
        inst, _ = self._setup()
        data = create_mock(["__len__", "get"])
        data.get.return_value = b"dead beef"
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_end, data, False)


class TestSibraExtBaseParseFlags(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_flags
    """
    def _check(self, flags, values, steady):
        inst = SibraExtBaseTesting()
        inst.STEADY = steady
        setup = values.pop(0)
        req = values.pop(0)
        # Call
        ntools.eq_(inst._parse_flags(flags), req)
        # Tests
        ntools.eq_(inst.setup, setup)
        ntools.eq_(inst.accepted, values.pop(0))
        ntools.eq_(inst.error, values.pop(0))
        ntools.eq_(inst.steady, values.pop(0))
        ntools.eq_(inst.fwd, values.pop(0))
        ntools.eq_(inst.version, values.pop(0))

    def test(self):
        for flags, values, steady in FLAG_MAP:
            yield self._check, flags, list(values), steady


class TestSibraExtBaseParseBlock(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._parse_block
    """
    @patch("lib.sibra.ext.ext.ResvBlockSteady", autospec=True)
    def test_steady(self, resvb):
        inst = SibraExtBaseTesting()
        data = create_mock(["pop"])
        # Call
        ntools.eq_(inst._parse_block(data, 5, True), resvb.return_value)
        # Tests
        data.pop.assert_called_once_with(6 * inst.LINE_LEN)
        resvb.assert_called_once_with(data.pop.return_value)

    @patch("lib.sibra.ext.ext.ResvBlockEphemeral", autospec=True)
    def test_ephemeral(self, resvb):
        inst = SibraExtBaseTesting()
        data = create_mock(["pop"])
        # Call
        ntools.eq_(inst._parse_block(data, 0, False), resvb.return_value)
        # Tests
        resvb.assert_called_once_with(data.pop.return_value)


class TestSibraExtBasePackEnd(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._pack_end
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        inst._check_len = create_mock()
        expected = b"input"
        # Call
        ntools.eq_(inst._pack_end([b"input"]), expected)
        # Tests
        inst._check_len.assert_called_once_with(b"input")

    def test_full(self):
        inst = SibraExtBaseTesting()
        inst.path_ids = [bytes(range(3)), bytes(range(5))]
        for i in range(2):
            block = create_mock(["pack"])
            block.pack.return_value = ("active%d" % i).encode("ascii")
            inst.active_blocks.append(block)
        inst.req_block = create_mock(["pack"])
        inst.req_block.pack.return_value = b"req"
        inst._check_len = create_mock()
        expected = b"".join([b"input", bytes(range(3)),
                             bytes(range(5)), b"active0", b"active1", b"req"])
        # Call
        ntools.eq_(inst._pack_end([b"input"]), expected)


class TestSibraExtBasePackFlags(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._pack_flags
    """
    def _check(self, expected, flags, steady):
        inst = SibraExtBaseTesting()
        inst.STEADY = steady
        inst.setup = flags.pop(0)
        inst.req_block = flags.pop(0)
        inst.accepted = flags.pop(0)
        inst.error = flags.pop(0)
        inst.steady = flags.pop(0)
        inst.fwd = flags.pop(0)
        inst.version = flags.pop(0)
        # Call
        ntools.eq_(inst._pack_flags(), expected)

    def test(self):
        for flags, values, steady in FLAG_MAP:
            yield self._check, bytes([flags]), list(values), steady


class TestSibraExtBaseReverse(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.reverse
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.fwd, False)

    def test_accepted_setup(self):
        inst = SibraExtBaseTesting()
        inst.setup = True
        inst.fwd = False
        # Call
        inst.reverse()
        # Tests
        ntools.eq_(inst.setup, False)
        ntools.eq_(inst.req_block, None)


class TestSibraExtBaseSetSize(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase._set_size
    """
    def test_min(self):
        inst = SibraExtBaseTesting()
        inst._init_size = create_mock()
        # Call
        inst._set_size()
        # Tests
        inst._init_size.assert_called_once_with(0)

    def test_full(self):
        inst = SibraExtBaseTesting()
        inst._init_size = create_mock()
        inst.path_ids = ["abcd", "efgh"]
        inst.active_blocks = ["actblock0", "actblock1"]
        inst.req_block = "reqblock "
        # Call
        inst._set_size()
        # Tests
        inst._init_size.assert_called_once_with(4)


class TestSibraExtBaseProcess(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.process
    """
    def _check(self, local, fwd, dir_fwd, curr_hop):
        inst = SibraExtBaseTesting()
        inst.fwd = fwd
        inst._process = create_mock()
        # Call
        ntools.eq_(inst.process("state", "spkt", local, "key"),
                   inst._process.return_value)
        # Tests
        inst._process.assert_called_once_with("state", "spkt", dir_fwd, "key")
        ntools.eq_(inst.curr_hop, curr_hop)

    def test(self):
        for local, fwd, dir_fwd, curr_hop in (
            (True, True, True, 1),
            (True, False, False, -1),
            (False, False, True, 0),
            (False, True, False, 0),
        ):
            yield self._check, local, fwd, dir_fwd, curr_hop


class TestSibraExtBaseActiveSof(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.active_sof
    """
    def _check(self, curr_hop, expected):
        inst = SibraExtBaseTesting()
        inst.curr_hop = curr_hop
        for idx, sofs in enumerate(range(1, 4)):
            block = create_mock(["sofs"])
            block.sofs = []
            for j in range(sofs):
                block.sofs.append((idx, j))
            inst.path_lens.append(len(block.sofs))
            inst.active_blocks.append(block)
        # Call
        ntools.eq_(inst.active_sof(), expected)

    def test(self):
        for curr_hop, expected in (
            [0, (0, 0)], [1, (1, 0)], [2, (1, 1)],
            [3, (2, 0)], [4, (2, 1)], [5, (2, 2)],
        ):
            yield self._check, curr_hop, expected


class TestSibraExtBaseSwitchResv(object):
    """
    Unit tests for lib.sibra.ext.ext.SibraExtBase.switch_resv
    """
    def test(self):
        inst = SibraExtBaseTesting()
        inst._set_size = create_mock()
        inst.setup = True
        inst.req_block = "req block"
        inst.path_lens = [1, 2, 3]
        inst.total_hops = 6
        blocks = []
        for idx, sofs in enumerate(range(1, 4)):
            block = create_mock(["num_hops", "sofs"])
            block.sofs = []
            block.num_hops = sofs
            for j in range(sofs):
                block.sofs.append("sof %d-%d" % (idx, j))
            blocks.append(block)
        # Call
        inst.switch_resv(blocks)
        # Tests
        ntools.eq_(inst.setup, False)
        ntools.eq_(inst.path_lens, [1, 2, 3])
        ntools.eq_(inst.active_blocks, blocks)
        inst._set_size.assert_called_once_with()


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
