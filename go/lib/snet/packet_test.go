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

package snet_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestPacketSerializeDecodeLoop(t *testing.T) {
	decodedOHP := onehop.Path{}
	rawOHP := make([]byte, decodedOHP.Len())
	require.NoError(t, decodedOHP.SerializeTo(rawOHP))
	scionP := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []*path.InfoField{{ConsDir: true}},
		HopFields:  []*path.HopField{{ConsEgress: 4}, {ConsIngress: 1}},
	}
	rawSP := make([]byte, scionP.Len())
	require.NoError(t, scionP.SerializeTo(rawSP))

	testCases := map[string]snet.Packet{
		"UDP OHP packet": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawOHP,
					Type: onehop.PathType,
				},
				Payload: snet.UDPPayload{
					SrcPort: 25,
					DstPort: 1925,
					Payload: []byte("hello packet"),
				},
			},
		},
		"UDP packet": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.UDPPayload{
					SrcPort: 25,
					DstPort: 1925,
					Payload: []byte("hello packet"),
				},
			},
		},
		"SCMP EchoRequest": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPEchoRequest{
					Identifier: 4,
					SeqNumber:  3310,
					Payload:    []byte("echo request"),
				},
			},
		},
		"SCMP EchoReply": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPEchoReply{
					Identifier: 5,
					SeqNumber:  3410,
					Payload:    []byte("echo reply"),
				},
			},
		},
		"SCMP ExternalInterfaceDown": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPExternalInterfaceDown{
					IA:        xtest.MustParseIA("1-ff00:0:111"),
					Interface: 13,
					Payload:   []byte("scmp quote"),
				},
			},
		},
		"SCMP InternalConnectivityDown": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPInternalConnectivityDown{
					IA:      xtest.MustParseIA("1-ff00:0:111"),
					Ingress: 14,
					Egress:  25,
					Payload: []byte("scmp quote"),
				},
			},
		},
		"SCMP ParameterProblem": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPParameterProblemWithCode(
					snet.SCMPParameterProblem{
						Pointer: 16,
						Payload: []byte("scmp quote"),
					},
					slayers.SCMPCodePathExpired,
				),
			},
		},
		"SCMP PacketTooBig": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					Host: addr.SvcCS,
				},
				Source: snet.SCIONAddress{
					IA:   xtest.MustParseIA("1-ff00:0:112"),
					Host: addr.HostIPv4(net.ParseIP("127.0.0.1").To4()),
				},
				Path: spath.Path{
					Raw:  rawSP,
					Type: scion.PathType,
				},
				Payload: snet.SCMPPacketTooBig{
					MTU:     1503,
					Payload: []byte("scmp quote"),
				},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, tc.Serialize())
			actual := snet.Packet{Bytes: tc.Bytes}
			assert.NoError(t, actual.Decode())
			assert.Equal(t, tc.PacketInfo, actual.PacketInfo)
			assert.Equal(t, tc.PacketInfo.Payload, actual.PacketInfo.Payload)
			actual.Bytes = nil
			assert.NoError(t, actual.Serialize())
			assert.Equal(t, tc.Bytes, actual.Bytes)
		})
	}
}

func TestPacketSerialize(t *testing.T) {
	decodedOHP := onehop.Path{}
	rawOHP := make([]byte, decodedOHP.Len())
	decodedOHP.SerializeTo(rawOHP)

	testCases := map[string]struct {
		input     snet.Packet
		assertErr assert.ErrorAssertionFunc
	}{
		"valid UDP OHP": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:110"),
						Host: addr.SvcCS,
					},
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:112"),
						Host: addr.HostIPv4(net.ParseIP("127.0.0.1")),
					},
					Path: spath.Path{
						Raw:  rawOHP,
						Type: onehop.PathType,
					},
					Payload: snet.UDPPayload{
						SrcPort: 25,
						DstPort: 1925,
						Payload: []byte("hello packet"),
					},
				},
			},
			assertErr: assert.NoError,
		},
		"valid missing path": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:110"),
						Host: addr.SvcCS,
					},
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:112"),
						Host: addr.HostIPv4(net.ParseIP("127.0.0.1")),
					},
					Payload: snet.UDPPayload{
						SrcPort: 25,
						DstPort: 1925,
						Payload: []byte("hello packet"),
					},
				},
			},
			assertErr: assert.NoError,
		},
		"empty packet": {
			assertErr: assert.Error,
		},
		"missing payload": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:110"),
						Host: addr.SvcCS,
					},
					Source: snet.SCIONAddress{
						IA:   xtest.MustParseIA("1-ff00:0:112"),
						Host: addr.HostIPv4(net.ParseIP("127.0.0.1")),
					},
					Path: spath.Path{
						Raw:  rawOHP,
						Type: onehop.PathType,
					},
				},
			},
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.assertErr(t, tc.input.Serialize())
		})
	}
}
