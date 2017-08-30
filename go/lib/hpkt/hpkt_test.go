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
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
)

var (
	testParsePkt = "\x00\x41\x00\x2f\x03\x00\x00\x11\x06\x40\x00\x02\x06\x40\x00\x01" +
		"\xa9\xfe\x01\x02\xa9\xfe\x02\x02\xc3\x50\xc3\x50\x00\x17\x94\x8f" +
		"\x00\x00\x00\x0b\x10\x04\x50\x01\x01\x01\x02\x10\x01\x01\x1d"
	testWritePkt = "\x00\x41\x00\x40\x06\x03\x04\x11\x02\xa0\x00\x01\x04\x90\x04\x01" +
		"\x01\x02\x03\x04\x0a\x00\x00\x01\x01\x59\x78\xad\x54\x00\x64\x02" +
		"\x00\x3f\x02\x00\x00\x2e\x84\x50\x00\x3f\x00\x00\x1d\x8a\xad\x6c" +
		"\x05\x00\x00\x50\x00\x08\x64\x26\x73\x63\x69\x6f\x6e\x31\x32\x33"
)

func Test_ParseScnPkt(t *testing.T) {
	Convey("ScnPkt.Parse should load values correctly", t, func() {
		s := AllocScnPkt()
		err := ParseScnPkt(s, common.RawBytes(testParsePkt))

		SoMsg("error", err, ShouldBeNil)

		SoMsg("AddrHdr.DstIA.I", s.DstIA.I, ShouldEqual, 100)
		SoMsg("AddrHdr.DstIA.A", s.DstIA.A, ShouldEqual, 2)
		SoMsg("AddrHdr.SrcIA.I", s.SrcIA.I, ShouldEqual, 100)
		SoMsg("AddrHdr.SrcIA.A", s.SrcIA.A, ShouldEqual, 1)

		SoMsg("AddrHdr.DstHostAddr", s.DstHost.IP(), ShouldResemble, net.IP{169, 254, 1, 2})
		SoMsg("AddrHdr.SrcHostAddr", s.SrcHost.IP(), ShouldResemble, net.IP{169, 254, 2, 2})

		SoMsg("Path", s.Path.Raw, ShouldResemble, common.RawBytes{})
		SoMsg("Path.InfOff", s.Path.InfOff, ShouldEqual, 0)
		SoMsg("Path.HopOff", s.Path.HopOff, ShouldEqual, 0)

		udpHdr, ok := s.L4.(*l4.UDP)
		SoMsg("L4Hdr", ok, ShouldEqual, true)
		if !ok {
			t.Fatalf("Bad header, cannot continue")
		}

		SoMsg("UDP.SrcPort", udpHdr.SrcPort, ShouldEqual, 50000)
		SoMsg("UDP.DstPort", udpHdr.DstPort, ShouldEqual, 50000)
		SoMsg("UDP.Len", udpHdr.TotalLen, ShouldEqual, 23)
		SoMsg("UDP.Checksum", udpHdr.Checksum, ShouldResemble, common.RawBytes{0x94, 0x8f})

		buf := make(common.RawBytes, 1<<16)
		n, _ := s.Pld.WritePld(buf)
		SoMsg("Payload", buf[:n], ShouldResemble, common.RawBytes(testParsePkt[32:]))
	})
}

func Test_ScnPkt_Write(t *testing.T) {
	Convey("ScnPkt.Write should write values correctly", t, func() {
		s := AllocScnPkt()
		s.DstIA, _ = addr.IAFromString("42-1")
		s.SrcIA, _ = addr.IAFromString("73-1025")
		s.DstHost = addr.HostFromIP(net.IPv4(1, 2, 3, 4))
		s.SrcHost = addr.HostFromIP(net.IPv4(10, 0, 0, 1))
		s.Path.Raw = common.RawBytes("\x01\x59\x78\xad\x54\x00\x64\x02" +
			"\x00\x3f\x02\x00\x00\x2e\x84\x50" +
			"\x00\x3f\x00\x00\x1d\x8a\xad\x6c")
		s.Path.InfOff = 0
		s.Path.HopOff = 8
		s.L4 = &l4.UDP{SrcPort: 1280, DstPort: 80, TotalLen: 8}
		s.Pld = common.RawBytes("scion123")

		b := make(common.RawBytes, 1024)
		Convey("Normal write", func() {
			n, err := WriteScnPkt(s, b)
			SoMsg("Write error", err, ShouldBeNil)
			SoMsg("Buffer contents", b[:n], ShouldResemble, common.RawBytes(testWritePkt))
		})
	})
}
