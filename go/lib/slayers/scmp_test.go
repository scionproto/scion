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
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestSCMPDecodeFromBytes(t *testing.T) {
	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMP
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x5, 0x0, 0x10, 0x92, // header
			}, bytes.Repeat([]byte{0xff}, 15)...), // payload
			decoded: &slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(5, 0),
				Checksum: 4242,
			},
			assertFunc: assert.NoError,
		},
		"invalid small size": {
			raw:        []byte{0x5},
			decoded:    &slayers.SCMP{},
			assertFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := &slayers.SCMP{}
			err := got.DecodeFromBytes(tc.raw, gopacket.NilDecodeFeedback)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			assert.Equal(t, tc.decoded, got)
		})
	}
}

func TestSCMPSerializeTo(t *testing.T) {
	// scion header over which the pseudo checksum header is calculated.
	scnL := &slayers.SCION{
		DstIA: xtest.MustParseIA("1-ff00:0:4"),
	}
	err := scnL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()})
	assert.NoError(t, err)

	testCases := map[string]struct {
		raw        []byte
		decoded    *slayers.SCMP
		opts       gopacket.SerializeOptions
		assertFunc assert.ErrorAssertionFunc
	}{
		"valid": {
			raw: append([]byte{
				0x5, 0x0, 0x0, 0x0, // header
			}, bytes.Repeat([]byte{0xff}, 15)...), // payload
			decoded: &slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(5, 0),
			},
			opts:       gopacket.SerializeOptions{ComputeChecksums: false},
			assertFunc: assert.NoError,
		},
		"valid with checksum": {
			raw: append([]byte{
				0x5, 0x0, 0x49, 0xe3, // header
			}, bytes.Repeat([]byte{0xff}, 15)...), // payload
			decoded: &slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(5, 0),
			},
			opts:       gopacket.SerializeOptions{ComputeChecksums: true},
			assertFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.decoded.Contents = tc.raw[:4]
			tc.decoded.Payload = tc.raw[4:]
			buffer := gopacket.NewSerializeBuffer()
			require.NoError(t, tc.decoded.SetNetworkLayerForChecksum(scnL))
			err := tc.decoded.SerializeTo(buffer, tc.opts)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.raw[:len(tc.decoded.Contents)], buffer.Bytes())
		})
	}
}

func TestSCMP(t *testing.T) {
	testCases := map[string]struct {
		raw           []byte
		decodedLayers []gopacket.SerializableLayer
		opts          gopacket.SerializeOptions
		assertFunc    assert.ErrorAssertionFunc
	}{
		"destination unreachable": {
			raw: append([]byte{
				0x1, 0x6, 0x4e, 0xc9, // header SCMP
				0x0, 0x0, 0x00, 0x00, // header SCMP msg
			}, bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x1, 0x6, 0x4e, 0xc9, // header SCMP
						},
						Payload: append([]byte{
							0x0, 0x0, 0x00, 0x00,
						}, bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(1, slayers.SCMPCodeRejectRouteToDest),
					Checksum: 20169,
				},
				&slayers.SCMPDestinationUnreachable{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x0, 0x0, 0x00, 0x00,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		// "packet too big":          {},
		"parameter problem": {
			raw: append([]byte{
				0x4, 0x0, 0x4b, 0x8d, // header SCMP
				0x0, 0x0, 0x00, 0x42, // header SCMP msg
			}, bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x4, 0x0, 0x4b, 0x8d, // header SCMP
						},
						Payload: append([]byte{
							0x0, 0x0, 0x00, 0x42,
						}, bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(4, slayers.SCMPCodeErroneousHeaderField),
					Checksum: 19341,
				},
				&slayers.SCMPParameterProblem{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x0, 0x0, 0x00, 0x42,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					Pointer: 66,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"internal connectivity down": {
			raw: append([]byte{
				0x6, 0x0, 0x49, 0x94, // header SCMP
				0x0, 0x1, 0xff, 0x0, // start header SCMP msg
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0xf, // end  header SCMP msg
			}, bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x6, 0x0, 0x49, 0x94, // header SCMP
						},
						Payload: append([]byte{
							0x0, 0x1, 0xff, 0x0,
							0x0, 0x0, 0x1, 0x11,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x5,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0xf,
						}, bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(6, 0),
					Checksum: 18836,
				},
				&slayers.SCMPInternalConnectivityDown{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x0, 0x1, 0xff, 0x0, // header SCMP msg
							0x0, 0x0, 0x1, 0x11,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x5,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0xf,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					IA:      xtest.MustParseIA("1-ff00:0:111"),
					Ingress: 5,
					Egress:  15,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"external interface down": {
			raw: append([]byte{
				0x5, 0x0, 0x4a, 0xab, // header SCMP
				0x0, 0x1, 0xff, 0x0, // start header SCMP msg
				0x0, 0x0, 0x1, 0x11,
				0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x5, // end  header SCMP msg
			}, bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x5, 0x0, 0x4a, 0xab, // header SCMP
						},
						Payload: append([]byte{
							0x0, 0x1, 0xff, 0x0,
							0x0, 0x0, 0x1, 0x11,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x5,
						}, bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(5, 0),
					Checksum: 19115,
				},
				&slayers.SCMPExternalInterfaceDown{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x0, 0x1, 0xff, 0x0, // header SCMP msg
							0x0, 0x0, 0x1, 0x11,
							0x0, 0x0, 0x0, 0x0,
							0x0, 0x0, 0x0, 0x5,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					IA:   xtest.MustParseIA("1-ff00:0:111"),
					IfID: uint64(5),
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"echo request": {
			raw: append([]byte{
				0x80, 0x00, 0xca, 0x6b, // header SCMP
				0x00, 0x2a, 0x05, 0x39}, // start header SCMP msg
				bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x80, 0x0, 0xca, 0x6b,
						},
						Payload: append([]byte{
							0x00, 0x2a, 0x05, 0x39},
							bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0),
					Checksum: 51819,
				},
				&slayers.SCMPEcho{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x00, 0x2a, 0x05, 0x39,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					Identifier: 42,
					SeqNumber:  1337,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"echo reply": {
			raw: append([]byte{
				0x81, 0x00, 0xc9, 0x6b, // header SCMP
				0x00, 0x2a, 0x05, 0x39}, // start header SCMP msg
				bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x81, 0x0, 0xc9, 0x6b,
						},
						Payload: append([]byte{
							0x00, 0x2a, 0x05, 0x39},
							bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0),
					Checksum: 51563,
				},
				&slayers.SCMPEcho{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x00, 0x2a, 0x05, 0x39,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					Identifier: 42,
					SeqNumber:  1337,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"traceroute request": {
			raw: append([]byte{
				0x82, 0x00, 0xcd, 0x7c, // header SCMP
				0x00, 0x2a, 0x00, 0x00, // start header SCMP msg
				0x00, 0x01, 0xff, 0x00,
				0x00, 0x00, 0x01, 0x11,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x05},
				bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x82, 0x0, 0xcd, 0x7c,
						},
						Payload: append([]byte{
							0x00, 0x2a, 0x00, 0x00,
							0x00, 0x01, 0xff, 0x00,
							0x00, 0x00, 0x01, 0x11,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x05},
							bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
					Checksum: 52604,
				},
				&slayers.SCMPTraceroute{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x00, 0x2a, 0x00, 0x00,
							0x00, 0x01, 0xff, 0x00,
							0x00, 0x00, 0x01, 0x11,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x05,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					Identifier: 42,
					IA:         xtest.MustParseIA("1-ff00:0:111"),
					Interface:  5,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
		"traceroute reply": {
			raw: append([]byte{
				0x83, 0x00, 0xcc, 0x7c, // header SCMP
				0x00, 0x2a, 0x00, 0x00, // start header SCMP msg
				0x00, 0x01, 0xff, 0x00,
				0x00, 0x00, 0x01, 0x11,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x05},
				bytes.Repeat([]byte{0xff}, 15)...), // final payload
			decodedLayers: []gopacket.SerializableLayer{
				&slayers.SCMP{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x83, 0x0, 0xcc, 0x7c,
						},
						Payload: append([]byte{
							0x00, 0x2a, 0x00, 0x00,
							0x00, 0x01, 0xff, 0x00,
							0x00, 0x00, 0x01, 0x11,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x05},
							bytes.Repeat([]byte{0xff}, 15)...),
					},
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
					Checksum: 52348,
				},
				&slayers.SCMPTraceroute{
					BaseLayer: layers.BaseLayer{
						Contents: []byte{
							0x00, 0x2a, 0x00, 0x00,
							0x00, 0x01, 0xff, 0x00,
							0x00, 0x00, 0x01, 0x11,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x05,
						},
						Payload: bytes.Repeat([]byte{0xff}, 15),
					},
					Identifier: 42,
					IA:         xtest.MustParseIA("1-ff00:0:111"),
					Interface:  5,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 15)),
			},
			assertFunc: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			t.Run("decode", func(t *testing.T) {
				packet := gopacket.NewPacket(tc.raw, slayers.LayerTypeSCMP, gopacket.Default)
				pe := packet.ErrorLayer()
				if pe != nil {
					require.NoError(t, pe.Error())
				}
				// Check that there are exactly X layers, e.g SCMP, SCMPMSG & Payload.
				require.Equal(t, len(tc.decodedLayers), len(packet.Layers()))

				for _, l := range tc.decodedLayers {
					switch v := l.(type) {
					case gopacket.Payload:
						sl := packet.Layer(v.LayerType())
						require.NotNil(t, sl, "Payload should exist")
						s := sl.(*gopacket.Payload)
						assert.Equal(t, v.GoString(), s.GoString())
					default:
						assert.Equal(t, v, packet.Layer(v.LayerType()),
							fmt.Sprintf("%s layer", v.LayerType()))
					}
				}
				// TODO(karampok). it could give false positive if put SCMP/SCMP/PAYLOAD
				// assert.Empty(t, tc.decodedLayers, "all layers should have been tested")
			})

			t.Run("serialize", func(t *testing.T) {
				scnL := &slayers.SCION{
					DstIA: xtest.MustParseIA("1-ff00:0:4"),
				}
				err := scnL.SetDstAddr(&net.IPAddr{IP: net.ParseIP("174.16.4.1").To4()})
				assert.NoError(t, err)

				opts := gopacket.SerializeOptions{ComputeChecksums: true}
				got := gopacket.NewSerializeBuffer()
				for _, l := range tc.decodedLayers {
					switch v := l.(type) {
					case *slayers.SCMP:
						require.NoError(t, v.SetNetworkLayerForChecksum(scnL))
					}
				}

				err = gopacket.SerializeLayers(got, opts, tc.decodedLayers...)
				require.NoError(t, err)
				assert.Equal(t, tc.raw, got.Bytes())
			})
		})
	}
}
