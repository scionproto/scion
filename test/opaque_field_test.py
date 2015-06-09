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
:mod:`opaque_field_test` --- SCION opaque field tests
=====================================================
"""
# Stdlib
import struct
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType,
    OpaqueField,
    SupportSignatureField,
    SupportPeerField,
    SupportPCBField,
    TRCField,
)


class TestOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.__init__
    """
    def test_basic(self):
        op_fld = OpaqueField()
        ntools.eq_(op_fld.info, 0)
        ntools.eq_(op_fld.type, 0)
        ntools.assert_false(op_fld.parsed)
        ntools.assert_true(op_fld.raw is None)


class TestOpaqueFieldIsRegular(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_regular
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b10111111
        ntools.assert_true(op_fld.is_regular())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b01000000 
        ntools.assert_false(op_fld.is_regular())


class TestOpaqueFieldIsContinue(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_continue
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b11011111
        ntools.assert_false(op_fld.is_continue())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b00100000
        ntools.assert_true(op_fld.is_continue())


class TestOpaqueFieldIsXovr(object):
    """
    Unit tests for lib.packet.opaque_field.OpaqueField.is_xovr
    """
    def test_basic(self):
        op_fld = OpaqueField()
        op_fld.info = 0b11101111
        ntools.assert_false(op_fld.is_xovr())

    def test_set(self):
        op_fld = OpaqueField()
        op_fld.info = 0b00010000
        ntools.assert_true(op_fld.is_xovr())


class TestHopOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.__init__
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        ntools.eq_(hop_op_fld.exp_time, 0)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)
        ntools.assert_false(hop_op_fld.parsed)

    @patch("lib.packet.opaque_field.HopOpaqueField.parse")
    def test_raw(self, parse):
        hop_op_fld = HopOpaqueField("data")
        parse.assert_called_once_with("data")


class TestHopOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.parse
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01'*3
        hop_op_fld.parse(data)
        ntools.eq_(hop_op_fld.info, 0x0e)
        ntools.eq_(hop_op_fld.exp_time, 0x2a)
        ntools.eq_(hop_op_fld.ingress_if, 0x0a0)
        ntools.eq_(hop_op_fld.egress_if, 0xb0c)
        ntools.eq_(hop_op_fld.mac, b'\x01'*3)
        ntools.assert_true(hop_op_fld.parsed)

    def test_len(self):
        hop_op_fld = HopOpaqueField()
        hop_op_fld.parse(bytes.fromhex('0e 2a 0a 0b 0c 0d 0e'))
        ntools.assert_false(hop_op_fld.parsed)
        ntools.eq_(hop_op_fld.info, 0)
        ntools.eq_(hop_op_fld.exp_time, 0)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)


class TestHopOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.from_values
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField.from_values(42, 160, 2828, b'\x01'*3)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 160)
        ntools.eq_(hop_op_fld.egress_if, 2828)
        ntools.eq_(hop_op_fld.mac, b'\x01'*3)

    def test_less_arg(self):
        hop_op_fld = HopOpaqueField.from_values(42)
        ntools.eq_(hop_op_fld.exp_time, 42)
        ntools.eq_(hop_op_fld.ingress_if, 0)
        ntools.eq_(hop_op_fld.egress_if, 0)
        ntools.eq_(hop_op_fld.mac, b'\x00'*3)               


class TestHopOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.HopOpaqueField.pack
    """
    def test_basic(self):
        hop_op_fld = HopOpaqueField()
        hop_op_fld.info = 0x0e
        hop_op_fld.exp_time = 0x2a
        hop_op_fld.ingress_if = 0x0a0
        hop_op_fld.egress_if = 0xb0c
        hop_op_fld.mac = b'\x01'*3
        data = bytes.fromhex('0e 2a 0a 0b 0c') + b'\x01'*3
        ntools.eq_(hop_op_fld.pack(), data)


class TestInforOpaqueFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.__init__
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)
        ntools.assert_false(inf_op_fld.parsed)

    @patch("lib.packet.opaque_field.InfoOpaqueField.parse")
    def test_raw(self, parse):
        inf_op_fld = InfoOpaqueField("data")
        parse.assert_called_once_with("data")


class TestInfoOpaqueFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.parse
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(inf_op_fld.info, 0x0f>>1)
        ntools.eq_(inf_op_fld.timestamp, 0x2a0a0b0c)
        ntools.eq_(inf_op_fld.isd_id, 0x0d0e)
        ntools.eq_(inf_op_fld.hops, 0x0f)
        ntools.eq_(inf_op_fld.up_flag, 0x0f & 0x01)
        ntools.assert_true(inf_op_fld.parsed)

    def test_len(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(inf_op_fld.info, 0)
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)
        ntools.assert_false(inf_op_fld.parsed)


class TestInfoOpaqueFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.from_values
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField.from_values(7, True, 705301260, 3342, 15)
        ntools.eq_(inf_op_fld.info, 7)
        ntools.eq_(inf_op_fld.timestamp, 705301260)
        ntools.eq_(inf_op_fld.isd_id, 3342)
        ntools.eq_(inf_op_fld.hops, 15)
        ntools.assert_true(inf_op_fld.up_flag)

    def test_less_arg(self):
        inf_op_fld = InfoOpaqueField.from_values()
        ntools.eq_(inf_op_fld.info, 0)
        ntools.eq_(inf_op_fld.timestamp, 0)
        ntools.eq_(inf_op_fld.isd_id, 0)
        ntools.eq_(inf_op_fld.hops, 0)
        ntools.assert_false(inf_op_fld.up_flag)               


class TestInfoOpaqueFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.InfoOpaqueField.pack
    """
    def test_basic(self):
        inf_op_fld = InfoOpaqueField()
        inf_op_fld.info = 0x0f>>1
        inf_op_fld.timestamp = 0x2a0a0b0c
        inf_op_fld.isd_id = 0x0d0e
        inf_op_fld.hops = 0x0f
        inf_op_fld.up_flag = 0x0f & 0x01
        ntools.eq_(inf_op_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))


class TestTRCFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.__init__
    """
    def test_basic(self):
        trc_fld = TRCField()
        ntools.eq_(trc_fld.info, OpaqueFieldType.TRC_OF)
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)
        ntools.assert_false(trc_fld.parsed)

    @patch("lib.packet.opaque_field.TRCField.parse")
    def test_raw(self, parse):
        trc_fld = TRCField("data")
        parse.assert_called_once_with("data")


class TestTRCFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.parse
    """
    def test_basic(self):
        trc_fld = TRCField()
        trc_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(trc_fld.info, 0x0f)
        ntools.eq_(trc_fld.trc_version, 0x2a0a0b0c)
        ntools.eq_(trc_fld.if_id, 0x0d0e)
        ntools.eq_(trc_fld.reserved, 0x0f)
        ntools.assert_true(trc_fld.parsed)

    def test_len(self):
        trc_fld = TRCField()
        trc_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(trc_fld.info, OpaqueFieldType.TRC_OF)
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)
        ntools.assert_false(trc_fld.parsed)


class TestTRCFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.from_values
    """
    def test_basic(self):
        trc_fld = TRCField.from_values(705301260, 3342, 15)
        ntools.eq_(trc_fld.trc_version, 705301260)
        ntools.eq_(trc_fld.if_id, 3342)
        ntools.eq_(trc_fld.reserved, 15)

    def test_less_arg(self):
        trc_fld = TRCField.from_values()
        ntools.eq_(trc_fld.trc_version, 0)
        ntools.eq_(trc_fld.if_id, 0)
        ntools.eq_(trc_fld.reserved, 0)


class TestTRCFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.TRCField.pack
    """
    def test_basic(self):
        trc_fld = TRCField()
        trc_fld.info = 0x0f
        trc_fld.trc_version = 0x2a0a0b0c
        trc_fld.if_id = 0x0d0e
        trc_fld.reserved = 0x0f
        ntools.eq_(trc_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))


class TestSupportSignatureFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.SupportSignatureField.__init__
    """
    def test_basic(self):
        sup_sig_fld = SupportSignatureField()
        ntools.eq_(sup_sig_fld.cert_chain_version, 0)
        ntools.eq_(sup_sig_fld.sig_len, 0)
        ntools.eq_(sup_sig_fld.block_size, 0)
        ntools.assert_false(sup_sig_fld.parsed)

    @patch("lib.packet.opaque_field.SupportSignatureField.parse")
    def test_raw(self, parse):
        sup_sig_fld = SupportSignatureField("data")
        parse.assert_called_once_with("data")


class TestSupportSignatureFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.SupportSignatureField.parse
    """
    def test_basic(self):
        sup_sig_fld = SupportSignatureField()
        sup_sig_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(sup_sig_fld.cert_chain_version, 0x0f2a0a0b)
        ntools.eq_(sup_sig_fld.sig_len, 0x0c0d)
        ntools.eq_(sup_sig_fld.block_size, 0x0e0f)
        ntools.assert_true(sup_sig_fld.parsed)

    def test_len(self):
        sup_sig_fld = SupportSignatureField()
        sup_sig_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(sup_sig_fld.cert_chain_version, 0)
        ntools.eq_(sup_sig_fld.sig_len, 0)
        ntools.eq_(sup_sig_fld.block_size, 0)
        ntools.assert_false(sup_sig_fld.parsed)


class TestSupportSignatureFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.SupportSignatureField.from_values
    """
    def test_basic(self):
        sup_sig_fld = SupportSignatureField.from_values(3599, 254413323, 3085)
        ntools.eq_(sup_sig_fld.cert_chain_version, 254413323)
        ntools.eq_(sup_sig_fld.sig_len, 3085)
        ntools.eq_(sup_sig_fld.block_size, 3599)

    def test_less_arg(self):
        sup_sig_fld = SupportSignatureField.from_values(3599)
        ntools.eq_(sup_sig_fld.cert_chain_version, 0)
        ntools.eq_(sup_sig_fld.sig_len, 0)
        ntools.eq_(sup_sig_fld.block_size, 3599)


class TestSupportSignatureFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.SupportSignatureField.pack
    """
    def test_basic(self):
        sup_sig_fld = SupportSignatureField()
        sup_sig_fld.cert_chain_version = 0x0f2a0a0b
        sup_sig_fld.sig_len = 0x0c0d
        sup_sig_fld.block_size = 0x0e0f
        ntools.eq_(sup_sig_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))


class TestSupportPeerFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPeerField.__init__
    """
    def test_basic(self):
        sup_pr_fld = SupportPeerField()
        ntools.eq_(sup_pr_fld.isd_id, 0)
        ntools.eq_(sup_pr_fld.bwalloc_f, 0)
        ntools.eq_(sup_pr_fld.bwalloc_r, 0)
        ntools.eq_(sup_pr_fld.bw_class, 0)
        ntools.eq_(sup_pr_fld.reserved, 0)
        ntools.assert_false(sup_pr_fld.parsed)

    @patch("lib.packet.opaque_field.SupportPeerField.parse")
    def test_raw(self, parse):
        sup_pr_fld = SupportPeerField("data")
        parse.assert_called_once_with("data")


class TestSupportPeerFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPeerField.parse
    """
    def test_basic(self):
        sup_pr_fld = SupportPeerField()
        sup_pr_fld.parse(bytes.fromhex('0f 2a 0a 0b 81 0d 0e 0f'))
        ntools.eq_(sup_pr_fld.isd_id, 0x0f2a)
        ntools.eq_(sup_pr_fld.bwalloc_f, 0x0a)
        ntools.eq_(sup_pr_fld.bwalloc_r, 0x0b)
        data = struct.unpack("!I", bytes.fromhex('81 0d 0e 0f'))[0]
        bw_class = (data >> 31)
        reserved = data - (bw_class << 31)
        ntools.eq_(sup_pr_fld.bw_class, bw_class)
        ntools.eq_(sup_pr_fld.reserved, reserved)
        ntools.assert_true(sup_pr_fld.parsed)

    def test_len(self):
        sup_pr_fld = SupportPeerField()
        sup_pr_fld.parse(bytes.fromhex('0f 2a 0a 0b 81 0d 0e'))
        ntools.eq_(sup_pr_fld.isd_id, 0)
        ntools.eq_(sup_pr_fld.bwalloc_f, 0)
        ntools.eq_(sup_pr_fld.bwalloc_r, 0)
        ntools.eq_(sup_pr_fld.bw_class, 0)
        ntools.eq_(sup_pr_fld.reserved, 0)
        ntools.assert_false(sup_pr_fld.parsed)


class TestSupportPeerFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPeerField.from_values
    """
    def test_basic(self):
        sup_pr_fld = SupportPeerField.from_values(3882, 10, 11, 1, 17632783)
        ntools.eq_(sup_pr_fld.isd_id, 3882)
        ntools.eq_(sup_pr_fld.bwalloc_f, 10)
        ntools.eq_(sup_pr_fld.bwalloc_r, 11)
        ntools.eq_(sup_pr_fld.bw_class, 1)
        ntools.eq_(sup_pr_fld.reserved, 17632783)

    def test_less_arg(self):
        sup_pr_fld = SupportPeerField.from_values()
        ntools.eq_(sup_pr_fld.isd_id, 0)
        ntools.eq_(sup_pr_fld.bwalloc_f, 0)
        ntools.eq_(sup_pr_fld.bwalloc_r, 0)
        ntools.eq_(sup_pr_fld.bw_class, 0)
        ntools.eq_(sup_pr_fld.reserved, 0)


class TestSupportPeerFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPeerField.pack
    """
    def test_basic(self):
        sup_pr_fld = SupportPeerField()
        sup_pr_fld.isd_id = 0x0f2a
        sup_pr_fld.bwalloc_f = 0x0a
        sup_pr_fld.bwalloc_r = 0x0b
        data = struct.unpack("!I", bytes.fromhex('81 0d 0e 0f'))[0]
        sup_pr_fld.bw_class = (data >> 31)
        sup_pr_fld.reserved = data - (sup_pr_fld.bw_class << 31)
        ntools.eq_(sup_pr_fld.pack(),bytes.fromhex('0f 2a 0a 0b 81 0d 0e 0f'))


class TestSupportPCBFieldInit(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPCBField.__init__
    """
    def test_basic(self):
        sup_pcb_fld = SupportPCBField()
        ntools.eq_(sup_pcb_fld.isd_id, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.bebw_f, 0)
        ntools.eq_(sup_pcb_fld.bebw_r, 0)
        ntools.assert_false(sup_pcb_fld.parsed)

    @patch("lib.packet.opaque_field.SupportPCBField.parse")
    def test_raw(self, parse):
        sup_pcb_fld = SupportPCBField("data")
        parse.assert_called_once_with("data")


class TestSupportPCBFieldParse(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPCBField.parse
    """
    def test_basic(self):
        sup_pcb_fld = SupportPCBField()
        sup_pcb_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))
        ntools.eq_(sup_pcb_fld.isd_id, 0x0f2a)
        ntools.eq_(sup_pcb_fld.bwalloc_f, 0x0a)
        ntools.eq_(sup_pcb_fld.bwalloc_r, 0x0b)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_f, 0x0c)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_r, 0x0d)
        ntools.eq_(sup_pcb_fld.bebw_f, 0x0e)
        ntools.eq_(sup_pcb_fld.bebw_r, 0x0f)
        ntools.assert_true(sup_pcb_fld.parsed)

    def test_len(self):
        sup_pcb_fld = SupportPCBField()
        sup_pcb_fld.parse(bytes.fromhex('0f 2a 0a 0b 0c 0d 0e'))
        ntools.eq_(sup_pcb_fld.isd_id, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.bebw_f, 0)
        ntools.eq_(sup_pcb_fld.bebw_r, 0)
        ntools.assert_false(sup_pcb_fld.parsed)


class TestSupportPCBFieldFromValues(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPCBField.from_values
    """
    def test_basic(self):
        sup_pcb_fld = SupportPCBField.from_values(3882, 10, 11, 12, 13, 14, 15)
        ntools.eq_(sup_pcb_fld.isd_id, 3882)
        ntools.eq_(sup_pcb_fld.bwalloc_f, 10)
        ntools.eq_(sup_pcb_fld.bwalloc_r, 11)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_f, 12)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_r, 13)
        ntools.eq_(sup_pcb_fld.bebw_f, 14)
        ntools.eq_(sup_pcb_fld.bebw_r, 15)

    def test_less_arg(self):
        sup_pcb_fld = SupportPCBField.from_values()
        ntools.eq_(sup_pcb_fld.isd_id, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_f, 0)
        ntools.eq_(sup_pcb_fld.dyn_bwalloc_r, 0)
        ntools.eq_(sup_pcb_fld.bebw_f, 0)
        ntools.eq_(sup_pcb_fld.bebw_r, 0)


class TestSupportPCBFieldPack(object):
    """
    Unit tests for lib.packet.opaque_field.SupportPCBField.pack
    """
    def test_basic(self):
        sup_pcb_fld = SupportPCBField()
        sup_pcb_fld.isd_id = 0x0f2a
        sup_pcb_fld.bwalloc_f = 0x0a
        sup_pcb_fld.bwalloc_r = 0x0b
        sup_pcb_fld.dyn_bwalloc_f = 0x0c
        sup_pcb_fld.dyn_bwalloc_r = 0x0d
        sup_pcb_fld.bebw_f = 0x0e
        sup_pcb_fld.bebw_r = 0x0f
        ntools.eq_(sup_pcb_fld.pack(),bytes.fromhex('0f 2a 0a 0b 0c 0d 0e 0f'))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
