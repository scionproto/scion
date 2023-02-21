// Copyright 2022 ETH Zurich
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

package spao_test

import (
	"crypto/aes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/dchest/cmac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/spao"
)

func TestComputeAuthMac(t *testing.T) {
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	authKey := drkey.Key{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	sn := uint32(0x060504)
	ts := uint32(0x030201)
	fooPayload := []byte("some payload")
	decodedPath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0x03,
				CurrHF:  0x3b,
				SegLen:  [3]byte{1, 1, 1},
			},
			NumINF:  3,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				ConsDir:   false,
				SegID:     0xf001,
				Timestamp: ts,
			},
			{
				ConsDir:   false,
				SegID:     0xf002,
				Timestamp: ts,
			},
			{
				ConsDir:   true,
				SegID:     0xf003,
				Timestamp: ts,
			},
		},
		HopFields: []path.HopField{
			{
				EgressRouterAlert: true,
				ExpTime:           63,
				ConsIngress:       0,
				ConsEgress:        1,
				Mac:               [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
			{
				IngressRouterAlert: true,
				EgressRouterAlert:  true,
				ExpTime:            63,
				ConsIngress:        2,
				ConsEgress:         3,
				Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
			{
				IngressRouterAlert: true,
				ExpTime:            63,
				ConsIngress:        4,
				ConsEgress:         0,
				Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
		},
	}

	rawPath := make([]byte, decodedPath.Len())
	err := decodedPath.SerializeTo(rawPath)
	require.NoError(t, err)

	testCases := map[string]struct {
		optionParameter slayers.PacketAuthOptionParams
		scionL          slayers.SCION
		pld             []byte
		rawMACInput     []byte
		assertErr       assert.ErrorAssertionFunc
	}{
		"empty": {
			optionParameter: slayers.PacketAuthOptionParams{
				SPI:            slayers.PacketAuthSPI(0x1),
				Algorithm:      slayers.PacketAuthCMAC,
				Timestamp:      0x3e8,
				SequenceNumber: sn,
				Auth:           make([]byte, 16),
			},
			scionL: slayers.SCION{
				FlowID:       binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x12, 0x34}),
				TrafficClass: 0xff,
				NextHdr:      slayers.End2EndClass,
				SrcIA:        dstIA,
				DstIA:        dstIA,
				SrcAddrType:  slayers.T4Ip,
				RawSrcAddr:   net.IPv4(10, 1, 1, 11).To4(),
				DstAddrType:  slayers.T4Ip,
				RawDstAddr:   net.IPv4(10, 1, 1, 12).To4(),
				Path:         empty.Path{},
				PathType:     empty.PathType,
			},
			pld: fooPayload,
			rawMACInput: append([]byte{
				// 1. Authenticator Option Metadata
				0x9, 0xca, 0x0, 0xc, // HdrLen | Upper Layer | Upper-Layer Packet Length
				0x0, 0x0, 0x3, 0xe8, // Algorithm  | Timestamp
				0x0, 0x6, 0x5, 0x4, // RSV | Sequence Number
				// 2. SCION Common Header
				0x3, 0xf0, 0x12, 0x34, // Version | QoS | FlowID
				0x0, 0x0, 0x0, 0x0, // PathType |DT |DL |ST |SL | RSV
				// 3.  SCION Address Header
				0xa, 0x1, 0x1, 0xb,
			}, fooPayload...),
			assertErr: assert.NoError,
		},
		"decoded": {
			optionParameter: slayers.PacketAuthOptionParams{
				SPI:            slayers.PacketAuthSPI(0x1),
				Algorithm:      slayers.PacketAuthCMAC,
				Timestamp:      0x3e8,
				SequenceNumber: sn,
				Auth:           make([]byte, 16),
			},
			scionL: slayers.SCION{
				FlowID:       binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x12, 0x34}),
				TrafficClass: 0xff,
				NextHdr:      slayers.End2EndClass,
				SrcIA:        srcIA,
				DstIA:        dstIA,
				SrcAddrType:  slayers.T16Ip,
				RawSrcAddr:   net.ParseIP("2001:cafe::1").To16(),
				DstAddrType:  slayers.T4Svc,
				RawDstAddr:   addr.HostSVCFromString("CS").Pack(),
				Path:         decodedPath,
				PathType:     decodedPath.Type(),
			},
			pld: fooPayload,
			rawMACInput: append([]byte{
				// 1. Authenticator Option Metadata
				0x1c, 0xca, 0x0, 0xc, // HdrLen | Upper Layer | Upper-Layer Packet Length
				0x0, 0x0, 0x3, 0xe8, // Algorithm  | Timestamp
				0x0, 0x6, 0x5, 0x4, // RSV | Sequence Number
				// 2. SCION Common Header
				0x3, 0xf0, 0x12, 0x34, // Version | QoS | FlowID
				0x1, 0x43, 0x0, 0x0, // PathType |DT |DL |ST |SL | RSV
				// 3.  SCION Address Header
				0x20, 0x01, 0xca, 0xfe,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x1,
				// Zeroed-out path
				0x0, 0x0, 0x10, 0x41, // Path Meta Header (CurrINF, CurrHF = 0)
				0x0, 0x0, 0x0, 0x0, // Info[0] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x0, 0x0, 0x0, 0x0, // Info[1] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x1, 0x0, 0x0, 0x0, // Info[2] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x0, 0x3f, 0x0, 0x0, // Hop[0] (ConsIngress/Egress Alert = 0)
				0x0, 0x1, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
				0x0, 0x3f, 0x0, 0x2, // Hop[1] (ConsIngress/Egress Alert = 0)
				0x0, 0x3, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
				0x0, 0x3f, 0x0, 0x4, // Hop[2] (ConsIngress/Egress Router Alert = 0)
				0x0, 0x0, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
			}, fooPayload...),
			assertErr: assert.NoError,
		},
		"one hop": {
			optionParameter: slayers.PacketAuthOptionParams{
				SPI:            slayers.PacketAuthSPI(0x1),
				Algorithm:      slayers.PacketAuthCMAC,
				Timestamp:      0x3e8,
				SequenceNumber: sn,
				Auth:           make([]byte, 16),
			},
			scionL: slayers.SCION{
				FlowID:       binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x12, 0x34}),
				TrafficClass: 0xff,
				NextHdr:      slayers.End2EndClass,
				SrcIA:        srcIA,
				DstIA:        dstIA,
				SrcAddrType:  slayers.T4Ip,
				RawSrcAddr:   net.IPv4(192, 0, 0, 2).To4(),
				DstAddrType:  slayers.T4Ip,
				RawDstAddr:   net.IPv4(192, 0, 0, 1).To4(),
				Path: &onehop.Path{
					Info: path.InfoField{
						ConsDir:   false,
						SegID:     0xf001,
						Timestamp: ts,
					},

					FirstHop: path.HopField{
						EgressRouterAlert: true,
						ExpTime:           63,
						ConsIngress:       0,
						ConsEgress:        1,
						Mac:               [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
					SecondHop: path.HopField{
						IngressRouterAlert: true,
						ExpTime:            63,
						ConsIngress:        2,
						ConsEgress:         3,
						Mac:                [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				},
				PathType: onehop.PathType,
			},
			pld: fooPayload,
			rawMACInput: append([]byte{
				// 1. Authenticator Option Metadata
				0x11, 0xca, 0x0, 0xc, // HdrLen | Upper Layer | Upper-Layer Packet Length
				0x0, 0x0, 0x3, 0xe8, // Algorithm  | Timestamp
				0x0, 0x6, 0x5, 0x4, // RSV | Sequence Number
				// 2. SCION Common Header
				0x3, 0xf0, 0x12, 0x34, // Version | QoS | FlowID
				0x2, 0x0, 0x0, 0x0, // PathType |DT |DL |ST |SL | RSV
				// 3.  SCION Address Header
				0xc0, 0x0, 0x0, 0x2,
				// Zeroed-out path
				0x0, 0x0, 0x0, 0x0, // Info (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x0, 0x3f, 0x0, 0x0, // Hop[0] (ConsIngress/Egress Alert = 0)
				0x0, 0x1, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
				0x0, 0x0, 0x0, 0x0, // Hop[1] (zeroed-out)
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0,
			}, fooPayload...),
			assertErr: assert.NoError,
		},
		"epic": {
			optionParameter: slayers.PacketAuthOptionParams{
				SPI:            slayers.PacketAuthSPI(2 ^ 21 - 1),
				Algorithm:      slayers.PacketAuthCMAC,
				Timestamp:      0x3e8,
				SequenceNumber: sn,
				Auth:           make([]byte, 16),
			},
			scionL: slayers.SCION{
				FlowID:       binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x12, 0x34}),
				TrafficClass: 0xff,
				NextHdr:      slayers.End2EndClass,
				SrcIA:        srcIA,
				DstIA:        dstIA,
				SrcAddrType:  slayers.T4Ip,
				RawSrcAddr:   net.IPv4(192, 0, 0, 2).To4(),
				DstAddrType:  slayers.T4Ip,
				RawDstAddr:   net.IPv4(192, 0, 0, 1).To4(),
				PathType:     epic.PathType,
				Path: &epic.Path{
					PktID: epic.PktID{
						Timestamp: 1,
						Counter:   0x02000003,
					},
					PHVF: []byte{1, 2, 3, 4},
					LHVF: []byte{5, 6, 7, 8},
					ScionPath: &scion.Raw{
						Base: decodedPath.Base,
						Raw:  rawPath,
					},
				},
			},
			pld: fooPayload,
			rawMACInput: append([]byte{

				// 1. Authenticator Option Metadata
				0x1d, 0xca, 0x0, 0xc, // HdrLen | Upper Layer | Upper-Layer Packet Length
				0x0, 0x0, 0x3, 0xe8, // Algorithm  | Timestamp
				0x0, 0x6, 0x5, 0x4, // RSV | Sequence Number
				// 2. SCION Common Header
				0x3, 0xf0, 0x12, 0x34, // Version | QoS | FlowID
				0x3, 0x0, 0x0, 0x0, // PathType |DT |DL |ST |SL | RSV
				// 3.  SCION Address Header
				0xc0, 0x0, 0x0, 0x2,
				// Epic-HP header
				0x0, 0x0, 0x0, 0x1, 0x2, 0x0, 0x0, 0x3,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				// Zeroed-out path
				0x0, 0x0, 0x10, 0x41, // Path Meta Header (CurrINF, CurrHF = 0)
				0x0, 0x0, 0x0, 0x0, // Info[0] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x0, 0x0, 0x0, 0x0, // Info[1] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x1, 0x0, 0x0, 0x0, // Info[2] (SegID = 0)
				0x0, 0x3, 0x2, 0x1,
				0x0, 0x3f, 0x0, 0x0, // Hop[0] (ConsIngress/Egress Alert = 0)
				0x0, 0x1, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
				0x0, 0x3f, 0x0, 0x2, // Hop[1] (ConsIngress/Egress Alert = 0)
				0x0, 0x3, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
				0x0, 0x3f, 0x0, 0x4, // Hop[2] (ConsIngress/Egress Router Alert = 0)
				0x0, 0x0, 0x1, 0x2,
				0x3, 0x4, 0x5, 0x6,
			}, fooPayload...),
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			optAuth, err := slayers.NewPacketAuthOption(tc.optionParameter)
			assert.NoError(t, err)

			buf := make([]byte, spao.MACBufferSize)
			inpLen, err := spao.SerializeAuthenticatedData(
				buf,
				&tc.scionL,
				optAuth,
				slayers.L4SCMP,
				tc.pld,
			)
			require.NoError(t, err)
			require.Equal(t, tc.rawMACInput, append(buf[:inpLen], fooPayload...))

			mac, err := spao.ComputeAuthCMAC(
				spao.MACInput{
					authKey[:],
					optAuth,
					&tc.scionL,
					slayers.L4SCMP,
					tc.pld,
				},
				make([]byte, spao.MACBufferSize),
				optAuth.Authenticator(),
			)
			tc.assertErr(t, err)
			if err != nil {
				return
			}

			block, err := aes.NewCipher(authKey[:])
			require.NoError(t, err)
			macFunc, err := cmac.New(block)
			require.NoError(t, err)

			macFunc.Write(tc.rawMACInput)
			expectedMac := macFunc.Sum(nil)
			assert.Equal(t, expectedMac, mac)
		})
	}
}
