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
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ip6Addr = &net.IPAddr{IP: net.ParseIP("2001:db8::68")}
	ip4Addr = &net.IPAddr{IP: net.ParseIP("10.0.0.100").To4()}
	svcAddr = addr.HostSVCFromString("Wildcard")
	rawPath = []byte("\x00\x00\x20\x80\x00\x00\x01\x11\x00\x00\x01\x00\x01\x00\x02\x22\x00\x00" +
		"\x01\x00\x00\x3f\x00\x01\x00\x00\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x03\x00\x02\x01\x02" +
		"\x03\x04\x05\x06\x00\x3f\x00\x00\x00\x02\x01\x02\x03\x04\x05\x06\x00\x3f\x00\x01\x00\x00" +
		"\x01\x02\x03\x04\x05\x06")
)

func TestSCIONSerializeDecode(t *testing.T) {
	want := prepPacket(t, common.L4UDP)
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
			assert.Equal(t, tc.srcAddr, gotSrc)
			assert.Equal(t, tc.dstAddr, gotDst)
		})
	}

	s := &slayers.SCION{}
	assert.NoError(t, s.SetDstAddr(ip6Addr), "SetDstAddr()")
	assert.NoError(t, s.SetSrcAddr(ip4Addr), "SetSrcAddr()")

	dst, err := s.DstAddr()
	assert.NoError(t, err, "DstAddr()")
	src, err := s.SrcAddr()
	assert.NoError(t, err, "SrcAddr()")
	assert.Equal(t, ip6Addr, dst, "dstAddr")
	assert.Equal(t, ip4Addr, src, "srcAddr")
}

func TestPackAddr(t *testing.T) {
	testCases := map[string]struct {
		addr      net.Addr
		addrType  slayers.AddrType
		addrLen   slayers.AddrLen
		rawAddr   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		"pack IPv4": {
			addr:      ip4Addr,
			addrType:  slayers.T4Ip,
			addrLen:   slayers.AddrLen4,
			rawAddr:   []byte(ip4Addr.IP),
			errorFunc: assert.NoError,
		},
		"pack IPv6": {
			addr:      ip6Addr,
			addrType:  slayers.T16Ip,
			addrLen:   slayers.AddrLen16,
			rawAddr:   []byte(ip6Addr.IP),
			errorFunc: assert.NoError,
		},
		"pack SVC": {
			addr:      svcAddr,
			addrType:  slayers.T4Svc,
			addrLen:   slayers.AddrLen4,
			rawAddr:   svcAddr.PackWithPad(2),
			errorFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addrLen, addrType, rawAddr, err := slayers.PackAddr(tc.addr)
			tc.errorFunc(t, err)
			assert.Equal(t, tc.addrType, addrType)
			assert.Equal(t, tc.addrLen, addrLen)
			assert.Equal(t, tc.rawAddr, rawAddr)
		})
	}
}

func TestParseAddr(t *testing.T) {
	testCases := map[string]struct {
		addrType  slayers.AddrType
		addrLen   slayers.AddrLen
		rawAddr   []byte
		want      net.Addr
		errorFunc assert.ErrorAssertionFunc
	}{
		"parse IPv4": {
			addrType:  slayers.T4Ip,
			addrLen:   slayers.AddrLen4,
			rawAddr:   []byte(ip4Addr.IP),
			want:      ip4Addr,
			errorFunc: assert.NoError,
		},
		"parse IPv6": {
			addrType:  slayers.T16Ip,
			addrLen:   slayers.AddrLen16,
			rawAddr:   []byte(ip6Addr.IP),
			want:      ip6Addr,
			errorFunc: assert.NoError,
		},
		"parse SVC": {
			addrType:  slayers.T4Svc,
			addrLen:   slayers.AddrLen4,
			rawAddr:   svcAddr.PackWithPad(2),
			want:      svcAddr,
			errorFunc: assert.NoError,
		},
		"parse unknown type": {
			addrType:  0,
			addrLen:   slayers.AddrLen8,
			rawAddr:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			want:      nil,
			errorFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := slayers.ParseAddr(tc.addrType, tc.addrLen, tc.rawAddr)
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
	s := prepPacket(b, common.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		s.SerializeTo(buffer, opts)
		buffer.Clear()
	}
}

func BenchmarkSerializeNoReuseBuffer(b *testing.B) {
	s := prepPacket(b, common.L4UDP)
	opts := gopacket.SerializeOptions{FixLengths: true}
	for i := 0; i < b.N; i++ {
		buffer := gopacket.NewSerializeBuffer()
		s.SerializeTo(buffer, opts)
	}
}

func prepPacket(t testing.TB, c common.L4ProtocolType) *slayers.SCION {
	t.Helper()
	spkt := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      c,
		PathType:     slayers.PathTypeSCION,
		DstAddrType:  slayers.T16Ip,
		DstAddrLen:   slayers.AddrLen16,
		SrcAddrType:  slayers.T4Ip,
		SrcAddrLen:   slayers.AddrLen4,
		DstIA:        xtest.MustParseIA("1-ff00:0:111"),
		SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
		Path:         &scion.Raw{},
	}
	spkt.SetDstAddr(ip6Addr)
	spkt.SetSrcAddr(ip4Addr)
	spkt.Path.DecodeFromBytes(rawPath)
	return spkt
}

func prepRawPacket(t testing.TB) []byte {
	t.Helper()
	spkt := prepPacket(t, common.L4UDP)
	buffer := gopacket.NewSerializeBuffer()
	spkt.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true})
	return buffer.Bytes()
}
