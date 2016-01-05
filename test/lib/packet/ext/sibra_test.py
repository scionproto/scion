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
:mod:`lib_packet_ext_sibra_test` --- lib.packet.ext.sibra unit tests
====================================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext.sibra import (
    OfferBlock,
    ResvBlock,
    ResvInfo,
    SIBRA_INTERVAL,
    SibraExt,
    SibraOpaqueField,
)
from test.testcommon import assert_these_calls, create_mock

FLAG_MAP = (
    # Steady setup accepted fwd
    (0b11101100, (True, True, True, False, True, True, 0)),
    # Ephemeral setup denied rev
    (0b11000000, (True, True, False, False, False, False, 0)),
    # Steady use error fwd
    (0b00111100, (False, False, True, True, True, True, 0)),
)


class TestSibraExtParse(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt._parse
    """
    def _setup(self, setup=True, req=True, accepted=True, steady=True):
        inst = SibraExt()
        inst._parse_flags = create_mock()
        inst._parse_path_id = create_mock()
        inst.setup = setup
        inst.req = req
        inst.steady = steady
        inst.accepted = accepted
        data = create_mock(["__len__", "pop"])
        data.__len__.return_value = 0
        data.pop.side_effect = 12, 5, bytes([4, 5, 0])
        return inst, data

    @patch("lib.packet.ext.sibra.HopByHopExtension._parse", autospec=True)
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test_ephemeral_setup_accepted(self, raw, super_parse):
        inst, data = self._setup(steady=False)
        inst._parse_block = create_mock()
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "SibraExt", inst.MIN_LEN, min_=True)
        super_parse.assert_called_once_with(inst, data)
        inst._parse_flags.assert_called_once_with(12)
        ntools.eq_(inst.curr_hop, 5)
        ntools.eq_(inst.total_hops, 2+3+4)
        assert_these_calls(inst._parse_path_id, [
            call(data, False), call(data, steady=True), call(data, steady=True),
        ])
        ntools.eq_(inst.path_ids, [inst._parse_path_id.return_value] * 3)
        assert_these_calls(inst._parse_block, [
            call(data, 4), call(data, 5), call(data, 4+5),
        ])
        ntools.eq_(inst.active_blocks, [inst._parse_block.return_value] * 2)
        ntools.eq_(inst.req_block, inst._parse_block.return_value)

    @patch("lib.packet.ext.sibra.HopByHopExtension._parse", autospec=True)
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test_steady_setup_denied(self, raw, super_parse):
        inst, data = self._setup(accepted=False)
        inst._parse_offers_block = create_mock()
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        inst._parse_offers_block.assert_called_once_with(data)
        ntools.eq_(inst.req_block, inst._parse_offers_block.return_value)


class TestSibraExtParseFlags(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt._parse_flags
    """
    def _check(self, flags, values):
        inst = SibraExt()
        # Call
        inst._parse_flags(flags)
        # Tests
        ntools.eq_(inst.setup, values.pop(0))
        ntools.eq_(inst.req, values.pop(0))
        ntools.eq_(inst.accepted, values.pop(0))
        ntools.eq_(inst.error, values.pop(0))
        ntools.eq_(inst.steady, values.pop(0))
        ntools.eq_(inst.fwd, values.pop(0))
        ntools.eq_(inst.version, values.pop(0))

    def test(self):
        for flags, values in FLAG_MAP:
            yield self._check, flags, list(values)


class TestSibraExtParseBlock(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt._parse_block
    """
    @patch("lib.packet.ext.sibra.ResvBlock", autospec=True)
    def test(self, resvb):
        inst = SibraExt()
        data = create_mock(["pop"])
        # Call
        ntools.eq_(inst._parse_block(data, 5), resvb.return_value)
        # Tests
        data.pop.assert_called_once_with(6 * inst.LINE_LEN)
        resvb.assert_called_once_with(data.pop.return_value)


class TestSibraExtSteadyFromValues(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt.steady_from_values
    """
    @patch("lib.packet.ext.sibra.os.urandom", autospec=True)
    @patch("lib.packet.ext.sibra.ResvBlock.from_values",
           new_callable=create_mock)
    def test(self, resvb_fv, urandom):
        isd_ad = create_mock(["pack"])
        isd_ad.pack.return_value = b"isd ad"
        urandom.return_value = b"random"
        # Call
        inst = SibraExt.steady_from_values(isd_ad, "req info", 40)
        # Tests
        ntools.assert_is_instance(inst, SibraExt)
        ntools.eq_(inst.setup, True)
        ntools.eq_(inst.req, True)
        urandom.assert_called_once_with(inst.STEADY_ID_LEN)
        ntools.eq_(inst.path_ids, [b"isd ad" b"random"])
        resvb_fv.assert_called_once_with("req info", num_hops=40)
        ntools.eq_(inst.req_block, resvb_fv.return_value)


class TestSibraExtEphemeralFromValues(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt.ephemeral_from_values
    """
    @patch("lib.packet.ext.sibra.os.urandom", autospec=True)
    @patch("lib.packet.ext.sibra.ResvBlock.from_values",
           new_callable=create_mock)
    def test(self, resvb_fv, urandom):
        isd_ad = create_mock(["pack"])
        isd_ad.pack.return_value = b"isd ad"
        urandom.return_value = b"random"
        steady_ids = ["steady0", "steady1", "steady2"]
        steady_blocks = []
        for i in 2, 3, 4:
            block = create_mock(["num_hops"])
            block.num_hops = i
            steady_blocks.append(block)
        # Call
        inst = SibraExt.ephemeral_from_values(isd_ad, "req info", steady_ids,
                                              steady_blocks)
        # Tests
        ntools.assert_is_instance(inst, SibraExt)
        ntools.eq_(inst.setup, True)
        ntools.eq_(inst.req, True)
        ntools.eq_(inst.steady, False)
        urandom.assert_called_once_with(inst.EPHEMERAL_ID_LEN)
        ntools.eq_(inst.path_ids, [b"isd ad" b"random"] + steady_ids)
        ntools.eq_(inst.active_blocks, steady_blocks)
        resvb_fv.assert_called_once_with("req info", num_hops=(2+3+4))
        ntools.eq_(inst.req_block, resvb_fv.return_value)


class TestSibraExtPack(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt.pack
    """
    def _setup(self, path_lens=(), req=True):
        inst = SibraExt()
        inst._pack_flags = create_mock()
        inst._pack_flags.return_value = b"F"
        inst._check_len = create_mock()
        inst.curr_hop = 7
        if path_lens:
            inst.total_hops = sum(path_lens)
        inst.path_ids.append(b"path id0")
        for i, plen in enumerate(path_lens):
            block = create_mock(["num_hops", "pack"])
            block.num_hops = plen
            block.pack.return_value = ("block %2d" % i).encode("ascii")
            inst.active_blocks.append(block)
            if i:
                inst.path_ids.append(("path id%d" % i).encode("ascii"))
        if req:
            block = create_mock(["pack"])
            block.pack.return_value = b"req pack"
            inst.req_block = block
        return inst

    def test_active_req(self):
        inst = self._setup(path_lens=[10])
        expected = b"".join([
            b"F", bytes([7, 10, 0, 0]), b"path id0", b"block  0", b"req pack",
        ])
        # Call
        ntools.eq_(inst.pack(), expected)
        inst._check_len.assert_called_once_with(expected)

    def test_active_multi(self):
        inst = self._setup(path_lens=[2, 4, 6], req=False)
        expected = b"".join([
            b"F", bytes([7, 2, 4, 6]), b"path id0", b"path id1", b"path id2",
            b"block  0", b"block  1", b"block  2",
        ])
        # Call
        ntools.eq_(inst.pack(), expected)

    def test_req_only(self):
        inst = self._setup()
        inst.total_hops = 10
        expected = b"".join([
            b"F", bytes([7, 10, 0, 0]), b"path id0", b"req pack"])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSibraExtPackFlags(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt._pack_flags
    """
    def _check(self, expected, flags):
        inst = SibraExt()
        inst.setup = flags.pop(0)
        inst.req = flags.pop(0)
        inst.accepted = flags.pop(0)
        inst.error = flags.pop(0)
        inst.steady = flags.pop(0)
        inst.fwd = flags.pop(0)
        inst.version = flags.pop(0)
        # Call
        ntools.eq_(inst._pack_flags(), expected)

    def test(self):
        for flags, values in FLAG_MAP:
            yield self._check, flags, list(values)


class TestSibraExtPackEphemeralSetup(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraExt._pack_ephemeral_setup
    """
    def test(self):
        inst = SibraExt()
        inst.path_ids = [b"eph id", b"active id0", b"active id1"]
        for i in range(2):
            block = create_mock(["pack"])
            block.pack.return_value = ("block pack %d" % i).encode("ascii")
            inst.active_blocks.append(block)
        expected = b"".join([
            b"active id0", b"block pack 0", b"active id1", b"block pack 1"])
        # Call
        ntools.eq_(inst._pack_ephemeral_setup(), expected)


class TestResvInfoParse(object):
    """
    Unit tests for lib.packet.ext.sibra.ResvInfo._parse
    """
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test(self, raw):
        inst = ResvInfo()
        data = create_mock(["pop"])
        data.pop.side_effect = bytes.fromhex("01234567"), 2, 4, 0b10101111, 7
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "ResvInfo", inst.LEN)
        ntools.eq_(inst.exp, 0x01234567 * SIBRA_INTERVAL)
        ntools.eq_(inst.bw_fwd, 2)
        ntools.eq_(inst.bw_rev, 4)
        ntools.eq_(inst.index, 0b1010)
        ntools.eq_(inst.fail_hop, 7)


class TestResvInfoPack(object):
    """
    Unit tests for lib.packet.ext.sibra.ResvInfo.pack
    """
    def test(self):
        inst = ResvInfo()
        inst.exp = 0x01234567 * SIBRA_INTERVAL
        inst.bw_fwd = 2
        inst.bw_rev = 4
        inst.index = 0b1010
        inst.fail_hop = 7
        expected = b"".join([bytes.fromhex("01234567"),
                             bytes([2, 4, 0b10100000, 7])])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestResvBlockParse(object):
    """
    Unit tests for lib.packet.ext.sibra.ResvBlock._parse
    """
    @patch("lib.packet.ext.sibra.SibraOpaqueField", autospec=True)
    @patch("lib.packet.ext.sibra.ResvInfo", autospec=True)
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test(self, raw, resvinfo, sof):
        inst = ResvBlock()
        sof.LEN = SibraOpaqueField.LEN
        data = create_mock(["__bool__", "__len__", "pop"])
        data.__bool__.side_effect = True, True, True
        data.__len__.return_value = sof.LEN * 2
        data.pop.side_effect = "resvinfo", bytes(range(sof.LEN)), bytes(sof.LEN)
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "ResvBlock", inst.MIN_LEN,
                                    min_=True)
        resvinfo.assert_called_once_with("resvinfo")
        ntools.eq_(inst.info, resvinfo.return_value)
        ntools.eq_(inst.num_hops, 2)
        sof.assert_called_once_with(bytes(range(sof.LEN)))
        ntools.eq_(inst.sofs, [sof.return_value])


class TestResvBlockPack(object):
    """
    Unit tests for lib.packet.ext.sibra.ResvBlock.pack
    """
    def test(self):
        inst = ResvBlock()
        inst.info = create_mock(["pack"])
        inst.info.pack.return_value = b"info"
        inst.num_hops = 5
        for i in range(3):
            sof = create_mock(["pack"])
            sof.pack.return_value = ("sof %d" % i).encode("ascii")
            inst.sofs.append(sof)
        expected = b"".join([
            b"info", b"sof 0", b"sof 1", b"sof 2", bytes(SibraOpaqueField.LEN),
            bytes(SibraOpaqueField.LEN)
        ])
        # Call
        ntools.eq_(inst.pack("path ids"), expected)
        # Tests
        inst.sofs[0].pack.assert_called_once_with(inst.info, "path ids", None)
        inst.sofs[1].pack.assert_called_once_with(inst.info, "path ids",
                                                  inst.sofs[0])
        inst.sofs[2].pack.assert_called_once_with(inst.info, "path ids",
                                                  inst.sofs[1])


class TestOfferBlockParse(object):
    """
    Unit tests for lib.packet.ext.sibra.OfferBlock._parse
    """
    @patch("lib.packet.ext.sibra.ResvInfo", autospec=True)
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test(self, raw, resvinfo):
        inst = OfferBlock()
        data = create_mock(["__bool__", "__len__", "pop"])
        data.__bool__.side_effect = True, True, True
        data.__len__.return_value = inst.OFFER_LEN * 7
        data.pop.side_effect = ("resvinfo", bytes([3, 4]), bytes([5, 6]),
                                bytes(2))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "OfferBlock", inst.MIN_LEN,
                                    min_=True)
        resvinfo.assert_called_once_with("resvinfo")
        ntools.eq_(inst.offer_hops, 7)
        ntools.eq_(inst.offers, [(3, 4), (5, 6)])


class TestOfferBlockFromValues(object):
    """
    Unit tests for lib.packet.ext.sibra.OfferBlock.from_values
    """
    def _check(self, hops):
        # Call
        inst = OfferBlock.from_values("info", hops, 1, 3)
        # Tests
        ntools.assert_is_instance(inst, OfferBlock)
        ntools.eq_(inst.info, "info")
        ntools.eq_(inst.offers, [(1, 3)])
        ntools.assert_greater_equal(inst.offer_hops, hops)
        ntools.eq_(inst.offer_hops % inst.OFFERS_PER_LINE, 0)

    def test(self):
        for hops in range(8):
            yield self._check, hops


class TestOfferBlockPack(object):
    """
    Unit tests for lib.packet.ext.sibra.OfferBlock.pack
    """
    def test(self):
        inst = OfferBlock()
        inst.info = create_mock(["pack"])
        inst.info.pack.return_value = b"infopack"
        inst.offer_hops = 8
        for i in range(5):
            inst.offers.append((i, i+10))
        expected = b"".join([
            b"infopack",
            bytes([0, 10, 1, 11, 2, 12, 3, 13, 4, 14, 0, 0, 0, 0, 0, 0]),
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSibraOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraOpaqueField._parse
    """
    @patch("lib.packet.ext.sibra.Raw", autospec=True)
    def test(self, raw):
        inst = SibraOpaqueField()
        data = create_mock(["pop"])
        data.pop.side_effect = (bytes.fromhex("00AA 99FF"),
                                bytes.fromhex("01234567"))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        ntools.eq_(inst.ingress, 0x00AA)
        ntools.eq_(inst.egress, 0x99FF)
        ntools.eq_(inst.mac, 0x01234567)


class TestSibraOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraOpaqueField.pack
    """
    def test(self):
        inst = SibraOpaqueField()
        inst.ingress = 0x00AA
        inst.egress = 0x99FF
        inst.mac = 0x01234567
        expected = bytes.fromhex("00AA 99FF 01234567")
        # Call
        ntools.eq_(inst.pack(), expected)


class TestSibraOpaqueFieldCalcMac(object):
    """
    Unit tests for lib.packet.ext.sibra.SibraOpaqueField.calc_mac
    """
    @patch("lib.packet.ext.sibra.cbcmac", autospec=True)
    def test(self, cbcmac):
        inst = SibraOpaqueField()
        inst.ingress = 0x00AA
        inst.egress = 0x99FF
        info = create_mock(["LEN", "pack"])
        info.LEN = ResvInfo.LEN
        info.pack.return_value = b"infopack"
        path_ids = (b"key0", b"key1")
        cbcmac.return_value = bytes(range(inst.MAC_LEN * 2))
        # Call
        ntools.eq_(inst.calc_mac("key", info, path_ids, b"prev_raw"),
                   bytes(range(inst.MAC_LEN)))
        # Tests
        cbcmac.assert_called_once_with("key", b"".join([
            bytes.fromhex("00AA 99FF"), b"infopac\x00", b"key0", b"key1",
            bytes(inst.MAX_PATH_IDS_LEN - 8), b"prev_raw",
        ]))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
