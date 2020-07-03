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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	rawUDPPktFilename  = "udp-scion.bin"
	rawScmpPktFilename = "scmp-rev.bin"
)

func TestParseScnPkt(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawUDPPktFilename)
	t.Log("ScnPkt.Parse should parse UDP/SCION packets correctly")

	s := &spkt.ScnPkt{}
	require.NoError(t, ParseScnPkt(s, raw), "Should parse without error")

	assert.Equal(t, s.DstIA.I, addr.ISD(2), "AddrHdr.DstIA.I")
	assert.Equal(t, s.DstIA.A, xtest.MustParseAS("ff00:0:222"), "AddrHdr.DstIA.A")
	assert.Equal(t, s.SrcIA.I, addr.ISD(1), "AddrHdr.SrcIA.I")
	assert.Equal(t, s.SrcIA.A, xtest.MustParseAS("ff00:0:133"), "AddrHdr.SrcIA.A")
	assert.Equal(t, s.DstHost.IP(), net.IP{127, 2, 2, 222}, "AddrHdr.DstHostAddr")
	assert.Equal(t, s.SrcHost.IP(), net.IP{127, 1, 1, 111}, "AddrHdr.SrcHostAddr")
	cmnHdr, err := spkt.CmnHdrFromRaw(raw)
	require.NoError(t, err, "Bad common header, cannot continue")

	hdrLen := cmnHdr.HdrLenBytes()
	pathStart := spkt.CmnHdrLen + s.AddrLen()
	assert.Equal(t, s.Path.Raw, common.RawBytes(raw[pathStart:hdrLen]), "Path")

	udpHdr, ok := s.L4.(*l4.UDP)
	require.True(t, ok, "L4Hdr - Bad header")

	assert.Equal(t, udpHdr.SrcPort, uint16(3001), "UDP.SrcPort")
	assert.Equal(t, udpHdr.DstPort, uint16(3000), "UDP.DstPort")
	assert.Equal(t, udpHdr.TotalLen, uint16(len(raw)-hdrLen), "UDP.Len")
	assert.Equal(t, udpHdr.Checksum, common.RawBytes{0x1e, 0xb9}, "UDP.Checksum")

	buf := make(common.RawBytes, 1<<16)
	n, _ := s.Pld.WritePld(buf)
	assert.Equal(t, buf[:n], common.RawBytes(raw[hdrLen+l4.UDPLen:]), "Payload")
}

func TestParseSCMPRev(t *testing.T) {
	rawScmpPkt := xtest.MustReadFromFile(t, rawScmpPktFilename)
	t.Log("ScnPkt.Parse should load SCMP revocation packets correctly")

	s := &spkt.ScnPkt{}
	require.NoError(t, ParseScnPkt(s, rawScmpPkt), "Should parse without error")
	assert.Equal(t, len(s.HBHExt), 1, "HBH extension count")
	assert.Equal(t, len(s.E2EExt), 0, "E2E extension count")

	scmpHdr, ok := s.L4.(*scmp.Hdr)
	require.True(t, ok, "Bad L4Hdr, cannot continue")

	assert.Equal(t, scmpHdr.Class, scmp.C_Path, "SCMP.Class")
	assert.Equal(t, scmpHdr.Type, scmp.T_P_RevokedIF, "SCMP.Type")
	// if we regenerate the .bin then we must manually update the values, e.g. checksum
	assert.Equal(t, scmpHdr.TotalLen, uint16(0x158), "SCMP.Len")
	assert.Equal(t, scmpHdr.Checksum, common.RawBytes{0x4b, 0x52}, "SCMP.Checksum")
	assert.Equal(t, scmpHdr.Timestamp, uint64(0x57cd47224504d), "SCMP.Timestamp")
	cmnHdr, err := spkt.CmnHdrFromRaw(rawScmpPkt)
	require.NoError(t, err, "Bad common header, cannot continue")

	buf := make(common.RawBytes, 1<<16)
	n, _ := s.Pld.WritePld(buf)
	pldStart := cmnHdr.HdrLenBytes() + common.LineLen + scmp.HdrLen
	assert.Equal(t, buf[:n], common.RawBytes(rawScmpPkt[pldStart:]), "Payload")
}

func TestScnPktWrite(t *testing.T) {
	rawPath := common.RawBytes("\x01\x59\x78\xad\x54\x00\x64\x02" +
		"\x00\x3f\x02\x00\x00\x2e\x84\x50" +
		"\x00\x3f\x00\x00\x1d\x8a\xad\x6c")
	t.Log("Hpkt should be able to parse packets it writes.")
	s := &spkt.ScnPkt{}
	s.DstIA, _ = addr.IAFromString("42-ff00:0:300")
	s.SrcIA, _ = addr.IAFromString("73-ff00:0:301")
	s.DstHost = addr.HostFromIP(net.IPv4(1, 2, 3, 4))
	s.SrcHost = addr.HostFromIP(net.IPv4(10, 0, 0, 1))
	s.Path = &spath.Path{Raw: rawPath, InfOff: 0, HopOff: 8}
	s.L4 = &l4.UDP{SrcPort: 1280, DstPort: 80, TotalLen: 8}
	s.Pld = common.RawBytes("scion123")

	b := make(common.RawBytes, 1024)
	n, err := WriteScnPkt(s, b)
	assert.NoError(t, err, "Write error")

	c := &spkt.ScnPkt{}
	err = ParseScnPkt(c, b[:n])
	require.NoError(t, err, "Read error")
	assert.True(t, s.DstIA.Equal(c.DstIA), "Dst IAs must match")
	assert.True(t, s.SrcIA.Equal(c.SrcIA), "Src IAs must match")
	assert.Equal(t, s.DstHost.Type(), c.DstHost.Type(), "Dst host types must match")
	assert.True(t, s.DstHost.IP().Equal(c.DstHost.IP()), "Dst host IPs must match")
	assert.Equal(t, s.Path.Raw, c.Path.Raw, "Raw paths must match")
	assert.Equal(t, c.Path.InfOff, 0, "Info offset must be correct")
	assert.Equal(t, c.Path.HopOff, 8, "Hop offset must be correct")
	assert.Equal(t, s.L4.L4Type(), c.L4.L4Type(), "L4 type must match")
	assert.Equal(t, s.L4.L4Len(), c.L4.L4Len(), "L4 length must match")
	assert.Equal(t, s.Pld, c.Pld, "Payloads must match")
}

func TestParseMalformedPkts(t *testing.T) {

	makeCmnHdr := func(total, header, actual, ltype int) []byte {
		buf := make([]byte, total)
		c := spkt.CmnHdr{
			TotalLen: uint16(total),
			HdrLen:   uint8(header),
			NextHdr:  common.L4ProtocolType(ltype),
		}
		c.Write(buf)
		return buf[:actual]
	}

	tests := map[string][]byte{
		"actual size smaller than cmdnHdr min length ": makeCmnHdr(8, 1, 7, 0),
		"actual size is smaller than cmnHdr.TotalLen":  makeCmnHdr(16, 1, 15, 0),
		"actual size is larger than cmnHdr.TotalLen": append(makeCmnHdr(512, 64, 512,
			0), make([]byte, 25)...),
		"valid cmnHdr.TotalLen but invalid cmnHdr.HdrLen": makeCmnHdr(32, 64, 32, 0),
		"valid cmnHdr.{Total,Hdr}Len, invalid payload":    makeCmnHdr(512, 64, 512, 0),
		"valid cmdHdr, invalid type 0 header": append(makeCmnHdr(512+3, 64,
			512, 0), make([]byte, 3)...),
		"valid cmdHdr, invalid SCMP extension hdr": append(makeCmnHdr(512+3, 64, 512, 1),
			make([]byte, 3)...),
	}

	fs, err := ioutil.ReadDir("testdata/fuzz-inputs")
	require.NoError(t, err)
	for _, f := range fs {
		b := xtest.MustReadFromFile(t, filepath.Join("fuzz-inputs", f.Name()))
		tests[fmt.Sprintf("input %s", f.Name())] = b
	}

	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			s := &spkt.ScnPkt{}
			var err error
			w := func() {
				err = ParseScnPkt(s, b)
			}
			require.NotPanics(t, w)
			require.NotContains(t, err.Error(), "panic")
			require.Error(t, err, "Should parse with error")
		})
	}
}

func TestParseScnPkt2(t *testing.T) {
	raw := xtest.MustReadFromFile(t, "udp-scion-v2.bin")

	s := &spkt.ScnPkt{}
	require.NoError(t, ParseScnPkt2(s, raw), "Should parse without error")

	assert.Equal(t, addr.ISD(2), s.SrcIA.I, "SrcIA.I")
	assert.Equal(t, xtest.MustParseAS("ff00:0:222"), s.SrcIA.A, "SrcIA.A")

	assert.Equal(t, addr.ISD(1), s.DstIA.I, "DstIA.I")
	assert.Equal(t, xtest.MustParseAS("ff00:0:111"), s.DstIA.A, "DstIA.A")

	assert.Equal(t, net.IP{10, 0, 0, 100}, s.SrcHost.IP(), "SrcHostAddr")
	assert.Equal(t, net.ParseIP("2001:db8::68"), s.DstHost.IP(), "DstHostAddr")

	assert.Equal(
		t,
		common.RawBytes(generatePath()),
		s.Path.Raw,
		"Path",
	)
	udpHdr, ok := s.L4.(*l4.UDP)
	require.True(t, ok, "L4Hdr - Bad header")
	assert.Equal(t, uint16(1280), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, uint16(80), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(0x408), udpHdr.TotalLen, "UDP.TotalLen")

	assert.Equal(
		t,
		common.RawBytes(generatePayload()),
		s.Pld,
		"Payload",
	)
}

func TestScnPktWrite2(t *testing.T) {
	testCases := []struct {
		Name           string
		ExpectedPacket *spkt.ScnPkt
	}{
		{
			Name: "udp",
			ExpectedPacket: &spkt.ScnPkt{
				SrcIA:   xtest.MustParseIA("2-ff00:0:222"),
				DstIA:   xtest.MustParseIA("1-ff00:0:111"),
				SrcHost: addr.HostFromIP(net.IP{10, 0, 0, 100}),
				DstHost: addr.HostFromIP(net.IP{0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0,
					0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68}),
				Path: spath.NewV2(generatePath(), false),
				L4: &l4.UDP{
					SrcPort:  1280,
					DstPort:  80,
					TotalLen: 1032,
					Checksum: []byte{0xbb, 0xda},
				},
				Pld: common.RawBytes(generatePayload()),
			},
		},
		{
			Name: "EchoRequest",
			ExpectedPacket: &spkt.ScnPkt{
				SrcIA:   xtest.MustParseIA("1-ff00:0:1"),
				DstIA:   xtest.MustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				DstHost: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_EchoRequest,
					TotalLen: 40,
					Checksum: []byte{0x4a, 0x20},
				},
				Pld: &scmp.Payload{
					Meta:    &scmp.Meta{InfoLen: uint8((&scmp.InfoEcho{}).Len())},
					Info:    &scmp.InfoEcho{Id: 0xdeadcafe},
					CmnHdr:  common.RawBytes{},
					AddrHdr: common.RawBytes{},
					PathHdr: common.RawBytes{},
					ExtHdrs: common.RawBytes{},
					L4Hdr:   common.RawBytes{},
				},
			},
		},
		{
			Name: "EchoReply",
			ExpectedPacket: &spkt.ScnPkt{
				SrcIA:   xtest.MustParseIA("1-ff00:0:1"),
				DstIA:   xtest.MustParseIA("1-ff00:0:1"),
				SrcHost: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				DstHost: addr.HostFromIP(net.IP{127, 0, 0, 1}),
				L4: &scmp.Hdr{
					Class: scmp.C_General, Type: scmp.T_G_EchoReply,
					TotalLen: 40,
					Checksum: common.RawBytes{0x4a, 0x1f},
				},
				Pld: &scmp.Payload{
					Meta: &scmp.Meta{
						InfoLen: uint8((&scmp.InfoEcho{}).Len()),
					},
					Info:    &scmp.InfoEcho{Id: 0xdeadcafe},
					CmnHdr:  common.RawBytes{},
					AddrHdr: common.RawBytes{},
					PathHdr: common.RawBytes{},
					ExtHdrs: common.RawBytes{},
					L4Hdr:   common.RawBytes{},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			b := make(common.RawBytes, common.MaxMTU)
			n, err := WriteScnPkt2(tc.ExpectedPacket, b)
			fmt.Println(b[:n])
			assert.NoError(t, err, "Write error")

			parsedPacket := &spkt.ScnPkt{}
			err = ParseScnPkt2(parsedPacket, b[:n])
			require.NoError(t, err, "Read error")

			assert.Equal(t, tc.ExpectedPacket, parsedPacket)
		})
	}
}

func generatePayload() []byte {
	b := make([]byte, 4*256)
	for i := 0; i < 4*256; i++ {
		b[i] = byte(i)
	}
	return b
}

func generatePath() []byte {
	return []byte{
		0x0, 0x0, 0x20, 0x80, 0x0, 0x0, 0x1, 0x11,
		0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x2, 0x22,
		0x0, 0x0, 0x1, 0x0, 0x0, 0x3f, 0x0, 0x1,
		0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x0,
		0x3f, 0x0, 0x3, 0x0, 0x2, 0x1, 0x2, 0x3,
		0x4, 0x5, 0x6, 0x0, 0x3f, 0x0, 0x0, 0x0,
		0x2, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x0,
		0x3f, 0x0, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3,
		0x4, 0x5, 0x6,
	}
}
