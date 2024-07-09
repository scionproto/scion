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
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

var (
	ip6Addr    = addr.MustParseHost("2001:db8::68")
	ip4Addr    = addr.MustParseHost("10.0.0.100")
	ip4in6Addr = addr.MustParseHost("::ffff:10.0.0.100")
	svcAddr    = addr.MustParseHost("Wildcard")
	rawPath    = func() []byte {
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
	if err := sc.SetDstAddr(addr.MustParseHost("1.2.3.4")); err != nil {
		assert.NoError(t, err)
	}
	if err := sc.SetSrcAddr(addr.MustParseHost("5.6.7.8")); err != nil {
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
			require.NoError(t, pkt.Path.DecodeFromBytes(make([]byte, tc.pathLen)))

			buffer := gopacket.NewSerializeBuffer()
			err := pkt.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
			tc.assertErr(t, err)
		})
	}
}

func TestSetAndGetAddr(t *testing.T) {
	testCases := map[string]struct {
		srcAddr addr.Host
		dstAddr addr.Host
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

			assert.Equal(t, tc.srcAddr, gotSrc)
			assert.Equal(t, tc.dstAddr, gotDst)
		})
	}
}

func TestPackAddr(t *testing.T) {
	testCases := map[string]struct {
		addr      addr.Host
		addrType  slayers.AddrType
		rawAddr   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		"pack IPv4": {
			addr:      ip4Addr,
			addrType:  slayers.T4Ip,
			rawAddr:   ip4Addr.IP().AsSlice(),
			errorFunc: assert.NoError,
		},
		"pack IPv4-mapped IPv6": {
			addr:      ip4in6Addr,
			addrType:  slayers.T4Ip,
			rawAddr:   []byte{0xa, 0x0, 0x0, 0x64},
			errorFunc: assert.NoError,
		},
		"pack IPv6": {
			addr:      ip6Addr,
			addrType:  slayers.T16Ip,
			rawAddr:   ip6Addr.IP().AsSlice(),
			errorFunc: assert.NoError,
		},
		"pack SVC": {
			addr:      addr.HostSVC(addr.SvcWildcard),
			addrType:  slayers.T4Svc,
			rawAddr:   []byte{0, 0x10, 0, 0},
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
		want      addr.Host
		errorFunc assert.ErrorAssertionFunc
	}{
		"parse IPv4": {
			addrType:  slayers.T4Ip,
			rawAddr:   ip4Addr.IP().AsSlice(),
			want:      ip4Addr,
			errorFunc: assert.NoError,
		},
		"parse IPv6": {
			addrType:  slayers.T16Ip,
			rawAddr:   ip6Addr.IP().AsSlice(),
			want:      ip6Addr,
			errorFunc: assert.NoError,
		},
		"parse SVC": {
			addrType:  slayers.T4Svc,
			rawAddr:   []byte{0, 0x10, 0, 0},
			want:      addr.HostSVC(addr.SvcWildcard),
			errorFunc: assert.NoError,
		},
		"parse unknown type": {
			addrType:  0b0001, // T=0,Len=8
			rawAddr:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			want:      addr.Host{},
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

func TestUnkownAddrType(t *testing.T) {

	testCases := []struct {
		addrType slayers.AddrType
		rawAddr  []byte
	}{
		{
			addrType: slayers.AddrType(0b1000), // T=2, L=0
			rawAddr:  []byte(`foo_`),           // 4 bytes
		},
		{
			addrType: slayers.AddrType(0b0001), // T=0, L=1
			rawAddr:  []byte(`foo_bar_`),       // 8 bytes
		},
		{
			addrType: slayers.AddrType(0b1110), // T=3, L=2
			rawAddr:  []byte(`foo_bar_boo_`),   // 12 bytes
		},
		{
			addrType: slayers.AddrType(0b0111),   // T=1, L=3
			rawAddr:  []byte(`foo_bar_boo_bop_`), // 16 bytes
		},
	}

	roundTrip := func(in *slayers.SCION) *slayers.SCION {
		// serialize
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, in.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}))

		// decode
		decoded := &slayers.SCION{}
		err := decoded.DecodeFromBytes(buffer.Bytes(), gopacket.NilDecodeFeedback)
		require.NoError(t, err)

		return decoded
	}

	for _, tc := range testCases {
		require.Equal(t, tc.addrType.Length(), len(tc.rawAddr)) // sanity check

		t.Run(fmt.Sprintf("src 0b%04b", tc.addrType), func(t *testing.T) {
			pkt := prepPacket(t, slayers.L4UDP)
			pkt.SrcAddrType = tc.addrType
			pkt.RawSrcAddr = tc.rawAddr

			got := roundTrip(pkt)
			assert.Equal(t, tc.addrType, got.SrcAddrType)
			assert.Equal(t, tc.rawAddr, got.RawSrcAddr)
		})

		t.Run(fmt.Sprintf("dest 0b%04b", tc.addrType), func(t *testing.T) {
			pkt := prepPacket(t, slayers.L4UDP)
			pkt.DstAddrType = tc.addrType
			pkt.RawDstAddr = tc.rawAddr

			got := roundTrip(pkt)
			assert.Equal(t, tc.addrType, got.DstAddrType)
			assert.Equal(t, tc.rawAddr, got.RawDstAddr)
		})
	}

}

func BenchmarkDecodePreallocNoParse(b *testing.B) {
	raw := prepRawPacket(b)
	s := &slayers.SCION{}
	for i := 0; i < b.N; i++ {
		err := s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
		require.NoError(b, err)
	}
}

func BenchmarkDecodeNoPreallocNoParse(b *testing.B) {
	raw := prepRawPacket(b)
	for i := 0; i < b.N; i++ {
		s := &slayers.SCION{}
		err := s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
		require.NoError(b, err)
	}
}

func BenchmarkDecodePreallocFull(b *testing.B) {
	raw := prepRawPacket(b)
	s := &slayers.SCION{}
	for i := 0; i < b.N; i++ {
		err := s.DecodeFromBytes(raw, gopacket.NilDecodeFeedback)
		require.NoError(b, err)
		p := s.Path.(*scion.Raw)
		_, err = p.ToDecoded()
		require.NoError(b, err)
	}
}

func BenchmarkSerializeReuseBuffer(b *testing.B) {
	s := prepPacket(b, slayers.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		err := s.SerializeTo(buffer, opts)
		require.NoError(b, err)
		err = buffer.Clear()
		require.NoError(b, err)
	}
}

func BenchmarkSerializeNoReuseBuffer(b *testing.B) {
	s := prepPacket(b, slayers.L4UDP)
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		buffer := gopacket.NewSerializeBuffer()
		err := s.SerializeTo(buffer, opts)
		require.NoError(b, err)
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
		DstIA:        addr.MustParseIA("1-ff00:0:111"),
		SrcIA:        addr.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
	}
	require.NoError(t, spkt.SetDstAddr(ip6Addr))
	require.NoError(t, spkt.SetSrcAddr(ip4Addr))
	require.NoError(t, spkt.Path.DecodeFromBytes(rawPath()))
	return spkt
}

func prepRawPacket(t testing.TB) []byte {
	t.Helper()
	spkt := prepPacket(t, slayers.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, spkt.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}))
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
					SrcIA: addr.MustParseIA("1-ff00:0:110"),
					DstIA: addr.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(addr.MustParseHost("174.16.4.1"))
				require.NoError(t, err)
				err = s.SetDstAddr(addr.MustParseHost("172.16.4.2"))
				require.NoError(t, err)
				return s
			},
			UpperLayer: xtest.MustParseHexString("aabbccdd"),
			Protocol:   1,
			Checksum:   0x2615,
		},
		"IPv4/IPv4 odd length": {
			Header: func(t *testing.T) *slayers.SCION {
				s := &slayers.SCION{
					SrcIA: addr.MustParseIA("1-ff00:0:110"),
					DstIA: addr.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(addr.MustParseHost("174.16.4.1"))
				require.NoError(t, err)
				err = s.SetDstAddr(addr.MustParseHost("172.16.4.2"))
				require.NoError(t, err)
				return s
			},
			UpperLayer: xtest.MustParseHexString("aabbccddee"),
			Protocol:   1,
			Checksum:   0x3813,
		},
		"IPv4/IPv6": {
			Header: func(t *testing.T) *slayers.SCION {
				s := &slayers.SCION{
					SrcIA: addr.MustParseIA("1-ff00:0:110"),
					DstIA: addr.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(addr.MustParseHost("174.16.4.1"))
				require.NoError(t, err)
				err = s.SetDstAddr(addr.MustParseHost("dead::beef"))
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
					SrcIA: addr.MustParseIA("1-ff00:0:110"),
					DstIA: addr.MustParseIA("1-ff00:0:112"),
				}
				err := s.SetSrcAddr(addr.MustParseHost("174.16.4.1"))
				require.NoError(t, err)
				err = s.SetDstAddr(addr.HostSVC(addr.SvcCS))
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
			reference := referenceChecksum(append(
				pseudoHeader(t, s, len(ul), tc.Protocol),
				ul...,
			))

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

func referenceChecksum(data []byte) uint16 {
	// pad at end with 0
	if len(data)%2 == 1 {
		data = append(data, 0)
	}
	var csum uint32
	for i := 0; i+1 < len(data); i += 2 {
		csum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
