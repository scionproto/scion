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

package respool

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestDecodeBuffer(t *testing.T) {
	testCases := map[string]struct {
		Layers       func(t *testing.T) []gopacket.SerializableLayer
		Check        func(t *testing.T, pkt *Packet)
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"UDP": {
			Layers: func(t *testing.T) []gopacket.SerializableLayer {
				scion := scionLayer(t, common.L4UDP)
				udp := &slayers.UDP{
					UDP: layers.UDP{
						SrcPort: 1337,
						DstPort: 42,
					},
				}
				udp.SetNetworkLayerForChecksum(scion)
				pld := gopacket.Payload("I am a payload")
				return []gopacket.SerializableLayer{scion, udp, pld}
			},
			Check: func(t *testing.T, pkt *Packet) {
				assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), pkt.SCION.SrcIA)
				assert.Equal(t, 1337, int(pkt.UDP.SrcPort))
				assert.Equal(t, slayers.LayerTypeSCIONUDP, pkt.L4)
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP": {
			Layers: func(t *testing.T) []gopacket.SerializableLayer {
				scion := scionLayer(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeExternalInterfaceDown, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				scmpMsg := &slayers.SCMPExternalInterfaceDown{
					IA:   xtest.MustParseIA("1-ff00:0:110"),
					IfID: 42,
				}
				pld := gopacket.Payload("offending packet")
				return []gopacket.SerializableLayer{scion, scmp, scmpMsg, pld}
			},
			Check: func(t *testing.T, pkt *Packet) {
				assert.Equal(t, xtest.MustParseIA("1-ff00:0:110"), pkt.SCION.SrcIA)
				assert.Equal(t, slayers.SCMPTypeExternalInterfaceDown,
					int(pkt.SCMP.TypeCode.Type()))
				assert.Equal(t, slayers.LayerTypeSCMP, pkt.L4)
			},
			ErrAssertion: assert.NoError,
		},
		"TCP": {
			Layers: func(t *testing.T) []gopacket.SerializableLayer {
				scion := scionLayer(t, common.L4TCP)
				pld := gopacket.Payload("offending packet")
				return []gopacket.SerializableLayer{scion, pld}
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			buf := gopacket.NewSerializeBuffer()
			require.NoError(t, gopacket.SerializeLayers(buf, opts, tc.Layers(t)...))
			pkt := &Packet{
				HeaderV2: true,
				buffer:   buf.Bytes(),
			}
			err := pkt.decodeBuffer()
			tc.ErrAssertion(t, err)
			if err != nil {
				return
			}
			tc.Check(t, pkt)
		})
	}
}

func scionLayer(t *testing.T, l4 common.L4ProtocolType) *slayers.SCION {
	scion := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      l4,
		PathType:     slayers.PathTypeSCION,
		SrcIA:        xtest.MustParseIA("1-ff00:0:110"),
		DstIA:        xtest.MustParseIA("1-ff00:0:112"),
		Path: &scion.Decoded{
			Base: scion.Base{
				PathMeta: scion.MetaHdr{
					CurrHF: 2,
					SegLen: [3]uint8{3, 0, 0},
				},
				NumINF:  1,
				NumHops: 3,
			},
			InfoFields: []*path.InfoField{
				{SegID: 0x111, ConsDir: true, Timestamp: 0x100},
			},
			HopFields: []*path.HopField{
				{ConsIngress: 0, ConsEgress: 311},
				{ConsIngress: 131, ConsEgress: 141},
				{ConsIngress: 411, ConsEgress: 0},
			},
		},
	}
	require.NoError(t, scion.SetSrcAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 1}}))
	require.NoError(t, scion.SetDstAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 2}}))
	return scion
}
