// Copyright 2019 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package dispatcher

import (
	"bytes"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/dispatcher/internal/respool"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestGetDst(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := map[string]struct {
		Pkt          func(t *testing.T) *respool.Packet
		ExpectedDst  Destination
		ErrAssertion assert.ErrorAssertionFunc
	}{
		"unsupported L4": {
			Pkt: func(t *testing.T) *respool.Packet {
				return &respool.Packet{
					L4: 1337,
				}
			},
			ErrAssertion: assert.Error,
		},
		"UDP/SCION with IP destination is delivered by IP": {
			Pkt: func(t *testing.T) *respool.Packet {
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					UDP: slayers.UDP{
						UDP: layers.UDP{
							DstPort: 1337,
						},
					},
					L4: slayers.LayerTypeSCIONUDP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: UDPDestination{
				IA:     xtest.MustParseIA("1-ff00:0:110"),
				Public: &net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1337},
			},
			ErrAssertion: assert.NoError,
		},
		"UDP/SCION with SVC destination is delivered by SVC": {
			Pkt: func(t *testing.T) *respool.Packet {
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					UDP: slayers.UDP{
						UDP: layers.UDP{
							DstPort: 1337,
						},
					},
					L4: slayers.LayerTypeSCIONUDP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(addr.SvcCS))
				return pkt
			},
			ExpectedDst: SVCDestination{
				IA:  xtest.MustParseIA("1-ff00:0:110"),
				Svc: addr.SvcCS,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION EchoRequest, is sent to SCMP handler": {
			Pkt: func(t *testing.T) *respool.Packet {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  13,
					},
				)
				require.NoError(t, err)
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
						BaseLayer: layers.BaseLayer{
							Payload: buf.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				return pkt
			},
			ExpectedDst:  SCMPHandler{},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION EchoReply, is sent to SCMP destination": {
			Pkt: func(t *testing.T) *respool.Packet {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  13,
					},
				)
				require.NoError(t, err)
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0),
						BaseLayer: layers.BaseLayer{
							Payload: buf.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION TracerouteRequest, is sent to SCMP handler": {
			Pkt: func(t *testing.T) *respool.Packet {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
					},
				)
				require.NoError(t, err)
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
						BaseLayer: layers.BaseLayer{
							Payload: buf.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				return pkt
			},
			ExpectedDst:  SCMPHandler{},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION TracerouteReply, is sent to SCMP destination": {
			Pkt: func(t *testing.T) *respool.Packet {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
					},
				)
				require.NoError(t, err)
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
						BaseLayer: layers.BaseLayer{
							Payload: buf.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with offending UDP/SCION is delivered by IP": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4UDP)
				udp := &slayers.UDP{
					UDP: layers.UDP{
						SrcPort: 1337,
						DstPort: 42,
					},
				}
				udp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					udp,
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPExternalInterfaceDown{
						IA:   xtest.MustParseIA("1-ff00:0:111"),
						IfID: 141,
					},
					gopacket.Payload(buf.Bytes()),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeExternalInterfaceDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: UDPDestination{
				IA:     xtest.MustParseIA("1-ff00:0:110"),
				Public: &net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1337},
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with offending SCMP/SCION EchoRequest is delivered by ID": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					scmp,
					&slayers.SCMPEcho{Identifier: 42, SeqNumber: 16},
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPInternalConnectivityDown{
						IA:      xtest.MustParseIA("1-ff00:0:111"),
						Ingress: 131,
						Egress:  141,
					},
					gopacket.Payload(buf.Bytes()),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeInternalConnectivityDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with offending SCMP/SCION TracerouteRequest is delivered by ID": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					scmp,
					&slayers.SCMPTraceroute{Identifier: 42},
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPInternalConnectivityDown{
						IA:      xtest.MustParseIA("1-ff00:0:111"),
						Ingress: 131,
						Egress:  141,
					},
					gopacket.Payload(buf.Bytes()),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeInternalConnectivityDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with truncated UDP/SCION payload is delivered by IP": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4UDP)
				udp := &slayers.UDP{
					UDP: layers.UDP{
						SrcPort: 1337,
						DstPort: 42,
					},
				}
				udp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					udp,
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPExternalInterfaceDown{
						IA:   xtest.MustParseIA("1-ff00:0:111"),
						IfID: 141,
					},
					gopacket.Payload(buf.Bytes()[:len(buf.Bytes())-20]),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeExternalInterfaceDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: UDPDestination{
				IA:     xtest.MustParseIA("1-ff00:0:110"),
				Public: &net.UDPAddr{IP: net.IP{192, 168, 0, 1}, Port: 1337},
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with offending truncated EchoRequest is delivered by ID": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					scmp,
					&slayers.SCMPEcho{Identifier: 42, SeqNumber: 16},
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPInternalConnectivityDown{
						IA:      xtest.MustParseIA("1-ff00:0:111"),
						Ingress: 131,
						Egress:  141,
					},
					// Truncate the SCMP Echo data.
					gopacket.Payload(buf.Bytes()[:len(buf.Bytes())-20]),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeInternalConnectivityDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with offending truncated TracerouteRequest is delivered by ID": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					scmp,
					&slayers.SCMPTraceroute{Identifier: 42},
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPInternalConnectivityDown{
						IA:      xtest.MustParseIA("1-ff00:0:111"),
						Ingress: 131,
						Egress:  141,
					},
					// Truncate the SCMP Traceroute data.
					gopacket.Payload(buf.Bytes()[:len(buf.Bytes())-20]),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeInternalConnectivityDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ExpectedDst: SCMPDestination{
				IA: xtest.MustParseIA("1-ff00:0:110"),
				ID: 42,
			},
			ErrAssertion: assert.NoError,
		},
		"SCMP/SCION Error with partial UDP/SCION header is dropped": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4UDP)
				udp := &slayers.UDP{
					UDP: layers.UDP{
						SrcPort: 1337,
						DstPort: 42,
					},
				}
				udp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					udp,
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPExternalInterfaceDown{
						IA:   xtest.MustParseIA("1-ff00:0:111"),
						IfID: 141,
					},
					gopacket.Payload(buf.Bytes()[:len(buf.Bytes())-21]),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeExternalInterfaceDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ErrAssertion: assert.Error,
		},
		"SCMP/SCION Error with partial EchoRequest is dropped": {
			Pkt: func(t *testing.T) *respool.Packet {
				// Construct offending packet.
				scion := newSCIONHdr(t, common.L4SCMP)
				scmp := &slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
				}
				scmp.SetNetworkLayerForChecksum(scion)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					scion,
					scmp,
					&slayers.SCMPEcho{Identifier: 42, SeqNumber: 16},
					gopacket.Payload(bytes.Repeat([]byte{0xff}, 20)),
				)
				require.NoError(t, err)

				scmpPld := gopacket.NewSerializeBuffer()
				err = gopacket.SerializeLayers(scmpPld,
					gopacket.SerializeOptions{},
					&slayers.SCMPInternalConnectivityDown{
						IA:      xtest.MustParseIA("1-ff00:0:111"),
						Ingress: 131,
						Egress:  141,
					},
					// Only partially include the echo request information.
					gopacket.Payload(buf.Bytes()[:len(buf.Bytes())-21]),
				)
				require.NoError(t, err)

				// Construct packet received by dispatcher.
				pkt := &respool.Packet{
					SCION: slayers.SCION{
						DstIA: xtest.MustParseIA("1-ff00:0:110"),
					},
					SCMP: slayers.SCMP{
						TypeCode: slayers.CreateSCMPTypeCode(
							slayers.SCMPTypeInternalConnectivityDown, 0),
						BaseLayer: layers.BaseLayer{
							Payload: scmpPld.Bytes(),
						},
					},
					L4: slayers.LayerTypeSCMP,
				}
				require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
				return pkt
			},
			ErrAssertion: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			destination, err := getDst(tc.Pkt(t))
			tc.ErrAssertion(t, err)
			assert.Equal(t, tc.ExpectedDst, destination)
		})
	}
}

func TestSCMPHandlerReverse(t *testing.T) {
	testCases := map[string]struct {
		L4               func(t *testing.T) slayers.SCMP
		ExpectedTypeCode slayers.SCMPTypeCode
		ExpectedL4       func(t *testing.T) []gopacket.SerializableLayer
	}{
		"echo without data": {
			L4: func(t *testing.T) slayers.SCMP {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  12,
					},
				)
				require.NoError(t, err)
				return slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
					Checksum: 1337,
					BaseLayer: layers.BaseLayer{
						Payload: buf.Bytes(),
					},
				}
			},
			ExpectedTypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0),
			ExpectedL4: func(t *testing.T) []gopacket.SerializableLayer {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  12,
					},
				)
				require.NoError(t, err)
				pkt := gopacket.NewPacket(buf.Bytes(), slayers.LayerTypeSCMPEcho,
					gopacket.DecodeOptions{})
				echo := pkt.Layer(slayers.LayerTypeSCMPEcho)
				require.NotNil(t, echo)
				return []gopacket.SerializableLayer{echo.(gopacket.SerializableLayer)}
			},
		},
		"echo with data": {
			L4: func(t *testing.T) slayers.SCMP {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  12,
					},
					gopacket.Payload("I am the payload, please don't forget about me :)"),
				)
				require.NoError(t, err)
				return slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
					Checksum: 1337,
					BaseLayer: layers.BaseLayer{
						Payload: buf.Bytes(),
					},
				}
			},
			ExpectedTypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0),
			ExpectedL4: func(t *testing.T) []gopacket.SerializableLayer {
				pld := gopacket.Payload("I am the payload, please don't forget about me :)")
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPEcho{
						Identifier: 42,
						SeqNumber:  12,
					},
					pld,
				)
				require.NoError(t, err)
				pkt := gopacket.NewPacket(buf.Bytes(), slayers.LayerTypeSCMPEcho,
					gopacket.DecodeOptions{})
				echo := pkt.Layer(slayers.LayerTypeSCMPEcho)
				require.NotNil(t, echo)
				return []gopacket.SerializableLayer{echo.(gopacket.SerializableLayer), &pld}
			},
		},
		"traceroute without data": {
			L4: func(t *testing.T) slayers.SCMP {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
						IA:         xtest.MustParseIA("1-ff00:0:110"),
						Interface:  12,
					},
				)
				require.NoError(t, err)
				return slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
					Checksum: 1337,
					BaseLayer: layers.BaseLayer{
						Payload: buf.Bytes(),
					},
				}
			},
			ExpectedTypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
			ExpectedL4: func(t *testing.T) []gopacket.SerializableLayer {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
						IA:         xtest.MustParseIA("1-ff00:0:110"),
						Interface:  12,
					},
				)
				require.NoError(t, err)
				pkt := gopacket.NewPacket(buf.Bytes(), slayers.LayerTypeSCMPTraceroute,
					gopacket.DecodeOptions{})
				tr := pkt.Layer(slayers.LayerTypeSCMPTraceroute)
				require.NotNil(t, tr)
				return []gopacket.SerializableLayer{tr.(gopacket.SerializableLayer)}
			},
		},
		"traceroute with data": {
			L4: func(t *testing.T) slayers.SCMP {
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
						IA:         xtest.MustParseIA("1-ff00:0:110"),
						Interface:  12,
					},
					gopacket.Payload("I am the payload, please don't forget about me :)"),
				)
				require.NoError(t, err)
				return slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
					Checksum: 1337,
					BaseLayer: layers.BaseLayer{
						Payload: buf.Bytes(),
					},
				}
			},
			ExpectedTypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
			ExpectedL4: func(t *testing.T) []gopacket.SerializableLayer {
				pld := gopacket.Payload("I am the payload, please don't forget about me :)")
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(buf,
					gopacket.SerializeOptions{},
					&slayers.SCMPTraceroute{
						Identifier: 42,
						IA:         xtest.MustParseIA("1-ff00:0:110"),
						Interface:  12,
					},
					pld,
				)
				require.NoError(t, err)
				pkt := gopacket.NewPacket(buf.Bytes(), slayers.LayerTypeSCMPTraceroute,
					gopacket.DecodeOptions{})
				tr := pkt.Layer(slayers.LayerTypeSCMPTraceroute)
				require.NotNil(t, tr)
				return []gopacket.SerializableLayer{tr.(gopacket.SerializableLayer), &pld}
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Prepare original packet
			pkt := &respool.Packet{
				SCION: slayers.SCION{
					Version:      0,
					TrafficClass: 0xb8,
					FlowID:       0xdead,
					NextHdr:      common.L4SCMP,
					PathType:     scion.PathType,
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
							{ConsIngress: 0, ConsEgress: 311, Mac: bytes.Repeat([]byte{0x00}, 6)},
							{ConsIngress: 131, ConsEgress: 141, Mac: bytes.Repeat([]byte{0x01}, 6)},
							{ConsIngress: 411, ConsEgress: 0, Mac: bytes.Repeat([]byte{0x02}, 6)},
						},
					},
				},
				SCMP: tc.L4(t),
				L4:   slayers.LayerTypeSCMP,
			}
			require.NoError(t, pkt.SCION.SetSrcAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 1}}))
			require.NoError(t, pkt.SCION.SetDstAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 2}}))

			// Reverse packet
			raw, err := SCMPHandler{}.reverse(pkt)
			require.NoError(t, err)

			gpkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.DecodeOptions{})

			t.Run("check SCION header", func(t *testing.T) {
				scionL := gpkt.Layer(slayers.LayerTypeSCION).(*slayers.SCION)
				expected := &slayers.SCION{
					Version:      0,
					TrafficClass: 0xb8,
					FlowID:       0xdead,
					HdrLen:       21,
					NextHdr:      common.L4SCMP,
					PayloadLen:   uint16(4 + len(pkt.SCMP.Payload)),
					PathType:     scion.PathType,
					SrcIA:        xtest.MustParseIA("1-ff00:0:112"),
					DstIA:        xtest.MustParseIA("1-ff00:0:110"),
					Path: &scion.Decoded{
						Base: scion.Base{
							PathMeta: scion.MetaHdr{
								CurrHF: 0,
								SegLen: [3]uint8{3, 0, 0},
							},
							NumINF:  1,
							NumHops: 3,
						},
						InfoFields: []*path.InfoField{
							{SegID: 0x111, ConsDir: false, Timestamp: 0x100},
						},
						HopFields: []*path.HopField{
							{ConsIngress: 411, ConsEgress: 0, Mac: bytes.Repeat([]byte{0x02}, 6)},
							{ConsIngress: 131, ConsEgress: 141, Mac: bytes.Repeat([]byte{0x01}, 6)},
							{ConsIngress: 0, ConsEgress: 311, Mac: bytes.Repeat([]byte{0x00}, 6)},
						},
					},
				}
				require.NoError(t, expected.SetSrcAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 2}}))
				require.NoError(t, expected.SetDstAddr(&net.IPAddr{IP: net.IP{127, 0, 0, 1}}))

				scionL.BaseLayer = layers.BaseLayer{}
				var decodedPath scion.Decoded
				require.NoError(t, decodedPath.DecodeFromBytes(scionL.Path.(*scion.Raw).Raw))
				scionL.Path = &decodedPath

				assert.Equal(t, expected, scionL)
			})
			t.Run("check L4", func(t *testing.T) {
				scmp := gpkt.Layer(slayers.LayerTypeSCMP)
				require.NotNil(t, scmp)
				assert.Equal(t, tc.ExpectedTypeCode, scmp.(*slayers.SCMP).TypeCode)
				assert.NotZero(t, scmp.(*slayers.SCMP).Checksum)

				for _, l := range tc.ExpectedL4(t) {
					assert.Equal(t, l, gpkt.Layer(l.LayerType()), l.LayerType().String())
				}
			})
		})
	}
}

func newSCIONHdr(t *testing.T, l4 common.L4ProtocolType) *slayers.SCION {
	scion := &slayers.SCION{
		NextHdr:  l4,
		PathType: scion.PathType,
		SrcIA:    xtest.MustParseIA("1-ff00:0:110"),
		DstIA:    xtest.MustParseIA("1-ff00:0:112"),
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
	require.NoError(t, scion.SetSrcAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 1}}))
	require.NoError(t, scion.SetDstAddr(&net.IPAddr{IP: net.IP{192, 168, 0, 2}}))
	return scion
}
