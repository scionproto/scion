package spkt

import (
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
)

var testPacket = "\x00\x41\x00\x2f\x03\x00\x00\x11\x06\x40\x00\x02\x06\x40\x00\x01" +
	"\xa9\xfe\x01\x02\xa9\xfe\x02\x02\xc3\x50\xc3\x50\x00\x17\xb0\x73" +
	"\x00\x00\x00\x0b\x10\x04\x50\x01\x01\x01\x02\x10\x01\x01\x1d"

func Test_ScnPkt_Parse(t *testing.T) {
	Convey("ScnPkt.Parse should load values correctly", t, func() {
		s := NewScnPkt()
		err := s.Parse(common.RawBytes(testPacket))

		SoMsg("error", err, ShouldBeNil)

		SoMsg("CmnHdr.Version", s.CmnHdr.Ver, ShouldEqual, 0)
		SoMsg("CmnHdr.DstType", s.CmnHdr.DstType, ShouldEqual, addr.HostTypeIPv4)
		SoMsg("CmnHdr.SrcType", s.CmnHdr.SrcType, ShouldEqual, addr.HostTypeIPv4)
		SoMsg("CmnHdr.TotalLen", s.CmnHdr.TotalLen, ShouldEqual, 47)
		SoMsg("CmnHdr.HdrLen", s.CmnHdr.HdrLen, ShouldEqual, 3)
		SoMsg("CmnHdr.CurrInfoF", s.CmnHdr.CurrInfoF, ShouldEqual, 0)
		SoMsg("CmnHdr.CurrHopF", s.CmnHdr.CurrHopF, ShouldEqual, 0)
		SoMsg("CmnHdr.NextHdr", s.CmnHdr.NextHdr, ShouldEqual, 17)

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
		SoMsg("UDP.Checksum", udpHdr.Checksum, ShouldResemble, common.RawBytes{0xb0, 0x73})

		buf := make(common.RawBytes, 1<<16)
		n, _ := s.Pld.Write(buf)
		SoMsg("Payload", buf[:n], ShouldResemble, common.RawBytes(testPacket[32:]))
	})
}
