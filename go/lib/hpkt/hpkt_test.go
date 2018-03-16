// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hpkt

import (
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
)

var (
	rawUdpPkt  = MustLoad("testdata/udp-scion.bin")
	rawScmpPkt = MustLoad("testdata/scmp-rev.bin")
)

func MustLoad(path string) common.RawBytes {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Unable to load file: %v", err))
	}
	return common.RawBytes(data)
}

func Test_ParseScnPkt(t *testing.T) {
	Convey("ScnPkt.Parse should parse UDP/SCION packets correctly", t, func() {
		s := &spkt.ScnPkt{
			DstIA: addr.IA{},
			SrcIA: addr.IA{},
		}
		err := ParseScnPkt(s, rawUdpPkt)

		SoMsg("error", err, ShouldBeNil)

		SoMsg("AddrHdr.DstIA.I", s.DstIA.I, ShouldEqual, 2)
		SoMsg("AddrHdr.DstIA.A", s.DstIA.A, ShouldEqual, 25)
		SoMsg("AddrHdr.SrcIA.I", s.SrcIA.I, ShouldEqual, 1)
		SoMsg("AddrHdr.SrcIA.A", s.SrcIA.A, ShouldEqual, 10)

		SoMsg("AddrHdr.DstHostAddr", s.DstHost.IP(), ShouldResemble, net.IP{127, 2, 2, 222})
		SoMsg("AddrHdr.SrcHostAddr", s.SrcHost.IP(), ShouldResemble, net.IP{127, 1, 1, 111})
		pathStart := spkt.CmnHdrLen + addr.IABytes*2 + addr.HostLenIPv4*2
		pathLen := 104

		SoMsg("Path", s.Path.Raw, ShouldResemble, rawUdpPkt[pathStart:pathStart+pathLen])

		udpHdr, ok := s.L4.(*l4.UDP)
		SoMsg("L4Hdr", ok, ShouldEqual, true)
		if !ok {
			t.Fatalf("Bad header, cannot continue")
		}

		SoMsg("UDP.SrcPort", udpHdr.SrcPort, ShouldEqual, 34711)
		SoMsg("UDP.DstPort", udpHdr.DstPort, ShouldEqual, 3000)
		SoMsg("UDP.Len", udpHdr.TotalLen, ShouldEqual, 1144)
		SoMsg("UDP.Checksum", udpHdr.Checksum, ShouldResemble, common.RawBytes{0xa4, 0x06})

		buf := make(common.RawBytes, 1<<16)
		n, _ := s.Pld.WritePld(buf)
		SoMsg("Payload", buf[:n], ShouldResemble,
			common.RawBytes(rawUdpPkt[pathStart+pathLen+l4.UDPLen:]))
	})
}

func Test_ParseSCMPRev(t *testing.T) {
	Convey("ScnPkt.Parse should load SCMP revocation packets correctly", t, func() {
		s := &spkt.ScnPkt{}
		err := ParseScnPkt(s, rawScmpPkt)
		t.Logf("%#v", s)
		SoMsg("error", err, ShouldBeNil)
		SoMsg("HBH extension count", len(s.HBHExt), ShouldEqual, 1)
		SoMsg("E2E extension count", len(s.E2EExt), ShouldEqual, 0)

		scmpHdr, ok := s.L4.(*scmp.Hdr)
		SoMsg("L4Hdr", ok, ShouldEqual, true)
		if !ok {
			t.Fatalf("Bad header, cannot continue")
		}
		SoMsg("SCMP.Class", scmpHdr.Class, ShouldEqual, scmp.C_Path)
		SoMsg("SCMP.Type", scmpHdr.Type, ShouldEqual, scmp.T_P_RevokedIF)
		SoMsg("SCMP.Len", scmpHdr.TotalLen, ShouldEqual, 848)
		SoMsg("SCMP.Checksum", scmpHdr.Checksum, ShouldResemble, common.RawBytes{0xbc, 0x1b})
		SoMsg("SCMP.Timestamp", scmpHdr.Timestamp, ShouldEqual, 1521209247650504)

		buf := make(common.RawBytes, 1<<16)
		n, _ := s.Pld.WritePld(buf)
		pathLen := 104
		pldStart := spkt.CmnHdrLen + addr.IABytes*2 + addr.HostLenIPv4*2 +
			common.LineLen + pathLen + scmp.HdrLen
		SoMsg("Payload", buf[:n], ShouldResemble, common.RawBytes(rawScmpPkt[pldStart:]))
	})
}

func Test_ScnPkt_Write(t *testing.T) {
	rawPath := common.RawBytes("\x01\x59\x78\xad\x54\x00\x64\x02" +
		"\x00\x3f\x02\x00\x00\x2e\x84\x50" +
		"\x00\x3f\x00\x00\x1d\x8a\xad\x6c")
	Convey("Hpkt should be able to parse packets it writes.", t, func() {
		s := &spkt.ScnPkt{}
		s.DstIA, _ = addr.IAFromString("42-1")
		s.SrcIA, _ = addr.IAFromString("73-1025")
		s.DstHost = addr.HostFromIP(net.IPv4(1, 2, 3, 4))
		s.SrcHost = addr.HostFromIP(net.IPv4(10, 0, 0, 1))
		s.Path = &spath.Path{Raw: rawPath, InfOff: 0, HopOff: 8}
		s.L4 = &l4.UDP{SrcPort: 1280, DstPort: 80, TotalLen: 8}
		s.Pld = common.RawBytes("scion123")

		b := make(common.RawBytes, 1024)
		n, err := WriteScnPkt(s, b)
		SoMsg("Write error", err, ShouldBeNil)

		c := &spkt.ScnPkt{}
		err = ParseScnPkt(c, b[:n])
		SoMsg("Read error", err, ShouldBeNil)
		SoMsg("Dst IAs must match", s.DstIA.Eq(c.DstIA), ShouldBeTrue)
		SoMsg("Src IAs must match", s.SrcIA.Eq(c.SrcIA), ShouldBeTrue)
		SoMsg("Dst host types must match", s.DstHost.Type(), ShouldEqual, c.DstHost.Type())
		SoMsg("Dst host IPs must match", s.DstHost.IP().Equal(c.DstHost.IP()), ShouldBeTrue)
		SoMsg("Raw paths must match", s.Path.Raw, ShouldResemble, c.Path.Raw)
		SoMsg("Info offset must be correct", c.Path.InfOff, ShouldEqual, 0)
		SoMsg("Hop offset must be correct", c.Path.HopOff, ShouldEqual, 8)
		SoMsg("L4 type must match", s.L4.L4Type(), ShouldEqual, c.L4.L4Type())
		SoMsg("L4 length must match", s.L4.L4Len(), ShouldEqual, c.L4.L4Len())
		SoMsg("Payloads must match", s.Pld, ShouldResemble, c.Pld)
	})
}
