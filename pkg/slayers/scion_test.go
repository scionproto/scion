// Copyright 2020 Anapaya Systems
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

package slayers_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

var (
	ip6Addr = &net.IPAddr{IP: net.ParseIP("2001:db8::68")}
	ip4Addr = &net.IPAddr{IP: net.ParseIP("10.0.0.100").To4()}
	svcAddr = addr.HostSVCFromString("Wildcard")
	rawPath = func() []byte {
		return []byte("\x00\x00\x20\x80\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00" +
			"\x00\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x03\x00" +
			"\x02\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06\x00" +
			"\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06")
	}
)

func TestSCIONLayerString(t *testing.T) {
	ia1, err := addr.ParseIA("1-ff00:0:1")
	assert.NoError(t, err)
	ia2, err := addr.ParseIA("1-ff00:0:2")
	assert.NoError(t, err)
	sc := &slayers.SCION{
		TrafficClass: 226,
		FlowID:       12345,
		NextHdr:      slayers.L4UDP,
		DstIA:        ia1,
		SrcIA:        ia2,
	}
	if err := sc.SetDstAddr(&net.IPAddr{IP: net.ParseIP("1.2.3.4").To4()}); err != nil {
		assert.NoError(t, err)
	}
	if err := sc.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("5.6.7.8").To4()}); err != nil {
		assert.NoError(t, err)
	}

	expectBegin := `` +
		`SCION	{` +
		`Contents=[] ` +
		`Payload=[] ` +
		`Version=0 ` +
		`TrafficClass=226 ` +
		`FlowID=12345 ` +
		`NextHdr=UDP ` +
		`HdrLen=0 ` +
		`PayloadLen=0 `
	expectMiddle := `` +
		`DstAddrType=0 ` +
		`SrcAddrType=0 ` +
		`DstIA=1-ff00:0:1 ` +
		`SrcIA=1-ff00:0:2 ` +
		`RawDstAddr=[1, 2, 3, 4] ` +
		`RawSrcAddr=[5, 6, 7, 8] `
	expectEnd := `}`

	testCases := map[string]struct {
		pathType path.Type
		path     path.Path
		expect   string
	}{
		"empty": {
			pathType: empty.PathType,
			path:     empty.Path{},
			expect:   expectBegin + `PathType=Empty (0) ` + expectMiddle + `Path={}` + expectEnd,
		},
		"scion": {
			pathType: scion.PathType,
			path: &scion.Decoded{
				Base: scion.Base{
					PathMeta: scion.MetaHdr{
						CurrINF: 5,
						CurrHF:  6,
						SegLen:  [3]uint8{1, 2, 3},
					},
					NumINF:  10,
					NumHops: 11,
				},
				InfoFields: []path.InfoField{
					{
						Peer:  true,
						SegID: 222,
					},
				},
				HopFields: []path.HopField{
					{
						IngressRouterAlert: true,
						EgressRouterAlert:  false,
						ExpTime:            63,
						ConsIngress:        4,
						ConsEgress:         5,
						Mac:                [path.MacLen]byte{6, 7, 8, 9, 10, 11},
					},
				},
			},
			expect: expectBegin + `PathType=SCION (1) ` + expectMiddle +
				`Path={ ` +
				`PathMeta={` +
				`CurrInf: 5, ` +
				`CurrHF: 6, ` +
				`SegLen: [1 2 3]} ` +
				`NumINF=10 ` +
				`NumHops=11 ` +
				`InfoFields=[{` +
				`Peer: true, ` +
				`ConsDir: false, ` +
				`SegID: 222, ` +
				`Timestamp: 1970-01-01 00:00:00+0000` +
				`}] HopFields=[{` +
				`IngressRouterAlert=true ` +
				`EgressRouterAlert=false ` +
				`ExpTime=63 ` +
				`ConsIngress=4 ` +
				`ConsEgress=5 ` +
				`Mac=[6 7 8 9 10 11]` +
				`}]}` + expectEnd,
		},
		"onehop": {
			pathType: onehop.PathType,
			path: &onehop.Path{
				Info: path.InfoField{
					ConsDir:   true,
					SegID:     34,
					Timestamp: 1000,
				},
				FirstHop: path.HopField{
					ConsIngress: 5,
					ConsEgress:  6,
					ExpTime:     63,
					Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
				},
				SecondHop: path.HopField{
					ConsIngress: 2,
					ConsEgress:  3,
					ExpTime:     63,
					Mac:         [path.MacLen]byte{7, 8, 9, 10, 11, 12},
				},
			},
			expect: expectBegin + `PathType=OneHop (2) ` + expectMiddle +
				`Path={ ` +
				`Info={` +
				`Peer: false, ` +
				`ConsDir: true, ` +
				`SegID: 34, ` +
				`Timestamp: 1970-01-01 00:16:40+0000` +
				`} FirstHop={ ` +
				`IngressRouterAlert=false ` +
				`EgressRouterAlert=false ` +
				`ExpTime=63 ` +
				`ConsIngress=5 ` +
				`ConsEgress=6 ` +
				`Mac=[1 2 3 4 5 6]` +
				`} SecondHop={ ` +
				`IngressRouterAlert=false ` +
				`EgressRouterAlert=false ` +
				`ExpTime=63 ` +
				`ConsIngress=2 ` +
				`ConsEgress=3 ` +
				`Mac=[7 8 9 10 11 12]` +
				`}}` + expectEnd,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			sc.PathType = tc.pathType
			sc.Path = tc.path
			got := gopacket.LayerString(sc)
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestSCIONSerializeDecode(t *testing.T) {
	want := prepPacket(t, slayers.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, want.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}))

	got := &slayers.SCION{}
	assert.NoError(t, got.DecodeFromBytes(buffer.Bytes(), gopacket.NilDecodeFeedback),
		"DecodeFromBytes")

	// XXX(karampok). the serialize step above does not set the BaseLayer of the want struct.
	// We need to split the serialize/decode case.
	want.BaseLayer = got.BaseLayer
	assert.Equal(t, want, got)
}

func TestSCIONSerializeLengthCheck(t *testing.T) {
	pkt := prepPacket(t, slayers.L4UDP)
	baseLen := slayers.CmnHdrLen + pkt.AddrHdrLen()

	testCases := map[string]struct {
		pathLen   int
		assertErr assert.ErrorAssertionFunc
	}{
		"too long": {
			pathLen:   1021 - baseLen,
			assertErr: assert.Error,
		},
		"tight": {
			pathLen:   1020 - baseLen,
			assertErr: assert.NoError,
		},
		"odd": {
			pathLen:   17,
			assertErr: assert.Error,
		},
		"good": {
			pathLen:   16,
			assertErr: assert.NoError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			pkt.Path = path.NewRawPath()
			pkt.Path.DecodeFromBytes(make([]byte, tc.pathLen))

			buffer := gopacket.NewSerializeBuffer()
			err := pkt.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
			tc.assertErr(t, err)
		})
	}
}

func TestSetAndGetAddr(t *testing.T) {
	testCases := map[string]struct {
		srcAddr net.Addr
		dstAddr net.Addr
	}{
		"set/get IPv4/IPv4": {
			srcAddr: ip4Addr,
			dstAddr: ip4Addr,
		},
		"set/get IPv4/IPv6": {
			srcAddr: ip4Addr,
			dstAddr: ip6Addr,
		},
		"set/get IPv6/IPv6": {
			srcAddr: ip6Addr,
			dstAddr: ip6Addr,
		},
		"set/get IPv4/Svc": {
			srcAddr: ip4Addr,
			dstAddr: svcAddr,
		},
		"set/get IPv6/Svc": {
			srcAddr: ip6Addr,
			dstAddr: svcAddr,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := slayers.SCION{}
			assert.NoError(t, s.SetSrcAddr(tc.srcAddr))
			assert.NoError(t, s.SetDstAddr(tc.dstAddr))
			gotSrc, err := s.SrcAddr()
			assert.NoError(t, err)
			gotDst, err := s.DstAddr()
			assert.NoError(t, err)

			equalAddr := func(t *testing.T, expected, actual net.Addr) {
				if _, ok := expected.(*net.IPAddr); !ok {
					assert.Equal(t, expected, actual)
					return
				}
				assert.True(t, expected.(*net.IPAddr).IP.Equal(actual.(*net.IPAddr).IP))
			}
			equalAddr(t, tc.srcAddr, gotSrc)
			equalAddr(t, tc.dstAddr, gotDst)
		})
	}
}

func TestPackAddr(t *testing.T) {
	testCases := map[string]struct {
		addr      net.Addr
		addrType  slayers.AddrType
		rawAddr   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		"pack IPv4": {
			addr:      ip4Addr,
			addrType:  slayers.T4Ip,
			rawAddr:   []byte(ip4Addr.IP),
			errorFunc: assert.NoError,
		},
		"pack IPv6": {
			addr:      ip6Addr,
			addrType:  slayers.T16Ip,
			rawAddr:   []byte(ip6Addr.IP),
			errorFunc: assert.NoError,
		},
		"pack SVC": {
			addr:      svcAddr,
			addrType:  slayers.T4Svc,
			rawAddr:   svcAddr.PackWithPad(2),
			errorFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, len(tc.rawAddr), tc.addrType.Length()) // sanity check
			addrType, rawAddr, err := slayers.PackAddr(tc.addr)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.addrType, addrType)
			assert.Equal(t, tc.rawAddr, rawAddr)
		})
	}
}

func TestParseAddr(t *testing.T) {
	testCases := map[string]struct {
		addrType  slayers.AddrType
		rawAddr   []byte
		want      net.Addr
		errorFunc assert.ErrorAssertionFunc
	}{
		"parse IPv4": {
			addrType:  slayers.T4Ip,
			rawAddr:   []byte(ip4Addr.IP.To4()),
			want:      ip4Addr,
			errorFunc: assert.NoError,
		},
		"parse IPv6": {
			addrType:  slayers.T16Ip,
			rawAddr:   []byte(ip6Addr.IP),
			want:      ip6Addr,
			errorFunc: assert.NoError,
		},
		"parse SVC": {
			addrType:  slayers.T4Svc,
			rawAddr:   svcAddr.PackWithPad(2),
			want:      svcAddr,
			errorFunc: assert.NoError,
		},
		"parse unknown type": {
			addrType:  0b0001, // T=0,Len=8
			rawAddr:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.addrType.Length(), len(tc.rawAddr)) // sanity check
			got, err := slayers.ParseAddr(tc.addrType, tc.rawAddr)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func BenchmarkDecodePreallocNoParse(b *testing.B) {
	raw := prepRawPacket(b)
	s := &slayers.SCION{}
	for i := 0; i < b.N; i++ {
		s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
	}
}

func BenchmarkDecodeNoPreallocNoParse(b *testing.B) {
	raw := prepRawPacket(b)
	for i := 0; i < b.N; i++ {
		s := &slayers.SCION{}
		s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
	}
}

func BenchmarkDecodePreallocFull(b *testing.B) {
	raw := prepRawPacket(b)
	s := &slayers.SCION{}
	for i := 0; i < b.N; i++ {
		s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
		p := s.Path.(*scion.Raw)
		p.ToDecoded()
	}
}

func BenchmarkSerializeReuseBuffer(b *testing.B) {
	s := prepPacket(b, slayers.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		s.SerializeTo(buffer, opts)
		buffer.Clear()
	}
}

func BenchmarkSerializeNoReuseBuffer(b *testing.B) {
	s := prepPacket(b, slayers.L4UDP)
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		buffer := gopacket.NewSerializeBuffer()
		s.SerializeTo(buffer, opts)
	}
}

func prepPacket(t testing.TB, c slayers.L4ProtocolType) *slayers.SCION {
	t.Helper()
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      c,
		PathType:     scion.PathType,
		DstAddrType:  slayers.T16Ip,
		SrcAddrType:  slayers.T4Ip,
		DstIA:        xtest.MustParseIA("1-ff00:0:111"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
	}
	spkt.SetDstAddr(ip6Addr)
	spkt.SetSrcAddr(ip4Addr)
	spkt.Path.DecodeFromBytes(rawPath())
	return spkt
}

func prepRawPacket(t testing.TB) []byte {
	t.Helper()
	spkt := prepPacket(t, slayers.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	spkt.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
	return buffer.Bytes()
}

func TestSCIONComputeChecksum(t *testing.T) {
	testCases := map[string]struct {
		Header     func(t *testing.T) *slayers.SCION
		UpperLayer []byte
		Protocol   uint8
		Checksum   uint16
	}{
		"IPv4/IPv4": {
			Header: func(t *testing.T) *slayers.SCION {
				s := &slayers.SCION{
					SrcIA: xtest.MustParseIA("1-ff00:0:110"),
					DstIA: xtest.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()})
				require.NoError(t, err)
				err = s.SetDstAddr(&net.IPAddr{IP: net.ParseIP("172.16.4.2").To4()})
				require.NoError(t, err)
				return s
			},
			UpperLayer: xtest.MustParseHexString("aabbccdd"),
			Protocol:   1,
			Checksum:   0x2615,
		},
		"IPv4/IPv6": {
			Header: func(t *testing.T) *slayers.SCION {
				s := &slayers.SCION{
					SrcIA: xtest.MustParseIA("1-ff00:0:110"),
					DstIA: xtest.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()})
				require.NoError(t, err)
				err = s.SetDstAddr(&net.IPAddr{IP: net.ParseIP("dead::beef")})
				require.NoError(t, err)
				return s
			},
			UpperLayer: xtest.MustParseHexString("aabbccdd"),
			Protocol:   17,
			Checksum:   0x387a,
		},
		"IPv4/SVC": {
			Header: func(t *testing.T) *slayers.SCION {
				s := &slayers.SCION{
					SrcIA: xtest.MustParseIA("1-ff00:0:110"),
					DstIA: xtest.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()})
				require.NoError(t, err)
				err = s.SetDstAddr(addr.SvcCS)
				require.NoError(t, err)
				return s
			},
			UpperLayer: xtest.MustParseHexString("aabbccdd"),
			Protocol:   223,
			Checksum:   0xd547,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			s := tc.Header(t)

			// Prepend checksum field for testing.
			ul := append([]byte{0, 0}, tc.UpperLayer...)

			// Reference checksum
			reference := util.Checksum(pseudoHeader(t, s, len(ul), tc.Protocol), ul)

			// Compute checksum
			csum, err := s.ComputeChecksum(ul, tc.Protocol)
			require.NoError(t, err)
			assert.Equal(t, tc.Checksum, csum)
			assert.Equal(t, reference, csum)

			// The checksum over the packet with the checksum field set should
			// equal 0.
			binary.BigEndian.PutUint16(ul, csum)
			csum, err = s.ComputeChecksum(ul, tc.Protocol)
			require.NoError(t, err)
			assert.Equal(t, uint16(0), csum)
		})
	}
}

func pseudoHeader(t *testing.T, s *slayers.SCION, upperLayerLength int, protocol uint8) []byte {
	addrHdrLen := s.AddrHdrLen()
	pseudo := make([]byte, addrHdrLen+4+4)
	require.NoError(t, s.SerializeAddrHdr(pseudo))
	offset := addrHdrLen
	binary.BigEndian.PutUint32(pseudo[offset:], uint32(upperLayerLength))
	offset += 4
	binary.BigEndian.PutUint32(pseudo[offset:], uint32(protocol))
	return pseudo
}
