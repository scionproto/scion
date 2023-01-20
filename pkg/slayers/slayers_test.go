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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

var (
	rawUDPPktFilename  = "scion-udp.bin"
	rawFullPktFilename = "scion-udp-extn.bin"
	goldenDir          = "./testdata"
)

var update = xtest.UpdateGoldenFiles()

func TestSCIONSCMP(t *testing.T) {
	testCases := map[string]struct {
		rawFile       string
		decodedLayers []gopacket.SerializableLayer
		opts          gopacket.SerializeOptions
	}{
		"destination unreachable": {
			rawFile: filepath.Join(goldenDir, "scion-scmp-dest-unreachable.bin"),
			decodedLayers: []gopacket.SerializableLayer{
				prepPacket(t, slayers.L4SCMP),
				&slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable,
						slayers.SCMPCodeRejectRouteToDest),
				},
				&slayers.SCMPDestinationUnreachable{},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 18)),
			},
		},
		// "packet too big":          {},
		// "parameter problem":       {},
		"internal connectivity down": {
			rawFile: filepath.Join(goldenDir, "scion-scmp-int-conn-down.bin"),
			decodedLayers: []gopacket.SerializableLayer{
				prepPacket(t, slayers.L4SCMP),
				&slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(6, 0),
				},
				&slayers.SCMPInternalConnectivityDown{
					IA:      xtest.MustParseIA("1-ff00:0:111"),
					Ingress: 5,
					Egress:  15,
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 18)),
			},
		},
		"external interface down": {
			rawFile: filepath.Join(goldenDir, "scion-scmp-ext-int-down.bin"),
			decodedLayers: []gopacket.SerializableLayer{
				prepPacket(t, slayers.L4SCMP),
				&slayers.SCMP{
					TypeCode: slayers.CreateSCMPTypeCode(5, 0),
				},
				&slayers.SCMPExternalInterfaceDown{
					IA:   xtest.MustParseIA("1-ff00:0:111"),
					IfID: uint64(5),
				},
				gopacket.Payload(bytes.Repeat([]byte{0xff}, 18)),
			},
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run("decode", func(t *testing.T) {
			t.Parallel()
			if *update {
				t.Skip("flag -update updates golden files")
				return
			}
			raw, err := os.ReadFile(tc.rawFile)
			require.NoError(t, err)
			packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
			pe := packet.ErrorLayer()
			if pe != nil {
				require.NoError(t, pe.Error())
			}
			// Check that there are exactly X layers, e.g SCMP, SCMPMSG & Payload.
			require.Equal(t, len(tc.decodedLayers), len(packet.Layers()))

			for _, l := range tc.decodedLayers {
				switch v := l.(type) {
				case *slayers.SCION:
					sl := packet.Layer(slayers.LayerTypeSCION)
					require.NotNil(t, sl, "SCION layer should exist")
					s := sl.(*slayers.SCION)
					// TODO(karampok). initialize expected BaseLayer from the raw file.
					v.BaseLayer = s.BaseLayer
					assert.Equal(t, v, s)
				case *slayers.SCMP:
					sl := packet.Layer(slayers.LayerTypeSCMP)
					require.NotNil(t, sl, "SCMP layer should exist")
					s := sl.(*slayers.SCMP)
					v.BaseLayer = s.BaseLayer
					assert.Equal(t, v, s)
				case *slayers.SCMPDestinationUnreachable:
					sl := packet.Layer(slayers.LayerTypeSCMPDestinationUnreachable)
					require.NotNil(t, sl, "SCMPDestinationUnreachable layer should exist")
					s := sl.(*slayers.SCMPDestinationUnreachable)
					v.BaseLayer = s.BaseLayer
					assert.Equal(t, v, s)
				case *slayers.SCMPExternalInterfaceDown:
					sl := packet.Layer(slayers.LayerTypeSCMPExternalInterfaceDown)
					require.NotNil(t, sl, "SCMPExternalInterfaceDown layer should exist")
					s := sl.(*slayers.SCMPExternalInterfaceDown)
					v.BaseLayer = s.BaseLayer
					assert.Equal(t, v, s)
				case *slayers.SCMPInternalConnectivityDown:
					sl := packet.Layer(slayers.LayerTypeSCMPInternalConnectivityDown)
					require.NotNil(t, sl, "SCMPInternalConnectivityDown layer should exist")
					s := sl.(*slayers.SCMPInternalConnectivityDown)
					v.BaseLayer = s.BaseLayer
					assert.Equal(t, v, s)
				case gopacket.Payload:
					sl := packet.Layer(gopacket.LayerTypePayload)
					require.NotNil(t, sl, "Payload should exist")
					s := sl.(*gopacket.Payload)
					assert.Equal(t, v.GoString(), s.GoString())
				default:
					assert.Fail(t, "all layers should match", "type %T", v)
				}
			}
		})

		t.Run("serialize", func(t *testing.T) {
			name, tc := name, tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: false,
				}
				// TODO(karampok). enable compute checksum, it requires refactor because
				//  scmp.SetNetworkLayerForChecksum(scion) should take place.
				got := gopacket.NewSerializeBuffer()
				err := gopacket.SerializeLayers(got, opts, tc.decodedLayers...)
				require.NoError(t, err)
				if *update {
					err := os.WriteFile(tc.rawFile, got.Bytes(), 0644)
					require.NoError(t, err)
					return
				}
				raw, err := os.ReadFile(tc.rawFile)
				require.NoError(t, err)
				assert.Equal(t, raw, got.Bytes())
			})
		})
	}
}

func TestPaths(t *testing.T) {
	testCases := map[string]struct {
		rawFile       string
		decodedLayers func(t *testing.T) []gopacket.SerializableLayer
	}{
		"empty path": {
			rawFile: filepath.Join(goldenDir, "empty-udp.bin"),
			decodedLayers: func(t *testing.T) []gopacket.SerializableLayer {
				s := &slayers.SCION{
					Version:      0,
					TrafficClass: 0xb8,
					FlowID:       0xdead,
					HdrLen:       12,
					PayloadLen:   1032,
					NextHdr:      slayers.L4UDP,
					PathType:     empty.PathType,
					DstAddrType:  slayers.T16Ip,
					SrcAddrType:  slayers.T4Ip,
					DstIA:        xtest.MustParseIA("1-ff00:0:111"),
					SrcIA:        xtest.MustParseIA("1-ff00:0:111"),
					Path:         empty.Path{},
				}
				require.NoError(t, s.SetDstAddr(ip6Addr))
				require.NoError(t, s.SetSrcAddr(ip4Addr))
				u := &slayers.UDP{
					SrcPort:  1280,
					DstPort:  80,
					Length:   1032,
					Checksum: 0xb8e4,
				}
				u.SetNetworkLayerForChecksum(s)
				return []gopacket.SerializableLayer{s, u, gopacket.Payload(mkPayload(1024))}
			},
		},
		"scion path": {
			rawFile: filepath.Join(goldenDir, "scion-udp.bin"),
			decodedLayers: func(t *testing.T) []gopacket.SerializableLayer {
				s := &slayers.SCION{
					Version:      0,
					TrafficClass: 0xb8,
					FlowID:       0xdead,
					HdrLen:       29,
					PayloadLen:   1032,
					NextHdr:      slayers.L4UDP,
					PathType:     scion.PathType,
					DstAddrType:  slayers.T16Ip,
					SrcAddrType:  slayers.T4Ip,
					DstIA:        xtest.MustParseIA("1-ff00:0:111"),
					SrcIA:        xtest.MustParseIA("2-ff00:0:222"),
					Path:         &scion.Raw{},
				}
				require.NoError(t, s.SetDstAddr(ip6Addr))
				require.NoError(t, s.SetSrcAddr(ip4Addr))
				require.NoError(t, s.Path.DecodeFromBytes(rawPath()))
				u := &slayers.UDP{
					SrcPort:  1280,
					DstPort:  80,
					Length:   1032,
					Checksum: 0xb7d2,
				}
				u.SetNetworkLayerForChecksum(s)
				return []gopacket.SerializableLayer{s, u, gopacket.Payload(mkPayload(1024))}
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run("decode: "+name, func(t *testing.T) {
			t.Parallel()
			if *update {
				t.Skip("flag -update updates golden files")
				return
			}
			raw, err := os.ReadFile(tc.rawFile)
			require.NoError(t, err)
			packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
			pe := packet.ErrorLayer()
			if pe != nil {
				require.NoError(t, pe.Error())
			}
			decoded := tc.decodedLayers(t)
			require.Equal(t, len(decoded), len(packet.Layers()))

			for _, l := range decoded {
				switch expected := l.(type) {
				case *slayers.SCION:
					sl := packet.Layer(slayers.LayerTypeSCION)
					require.NotNil(t, sl, "SCION layer should exist")
					s := sl.(*slayers.SCION)
					expected.BaseLayer = s.BaseLayer
					assert.Equal(t, gopacket.LayerString(expected), gopacket.LayerString(s))
				case *slayers.UDP:
					ul := packet.Layer(slayers.LayerTypeSCIONUDP)
					require.NotNil(t, ul, "UDP layer should exist")
					u := ul.(*slayers.UDP)
					expected.BaseLayer = u.BaseLayer
					assert.Equal(t, gopacket.LayerString(expected), gopacket.LayerString(u))
				}
			}
		})
		t.Run("serialize: "+name, func(t *testing.T) {
			t.Parallel()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			got := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(got, opts, tc.decodedLayers(t)...)
			require.NoError(t, err)
			if *update {
				err := os.WriteFile(tc.rawFile, got.Bytes(), 0644)
				require.NoError(t, err)
				return
			}
			raw, err := os.ReadFile(tc.rawFile)
			require.NoError(t, err)
			assert.Equal(t, raw, got.Bytes())
		})
	}
}

// TODO(shitz): Ideally, these would be table-driven tests.
func TestDecodeSCIONUDP(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawUDPPktFilename)

	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")

	// Check that there are exactly 3 layers (SCION, SCION/UDP, Payload)
	assert.Equal(t, 3, len(packet.Layers()), "Packet must have 3 layers")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	// Check SCION Header
	assert.Equal(t, scion.PathType, s.PathType)
	assert.Equal(t, uint8(29), s.HdrLen, "HdrLen")
	assert.Equal(t, uint16(1032), s.PayloadLen, "PayloadLen")
	assert.Equal(t, slayers.L4UDP, s.NextHdr, "CmnHdr.NextHdr")

	// Check SCION/UDP Header
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work

	assert.Equal(t, uint16(1280), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, uint16(80), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(1032), udpHdr.Length, "UDP.Len")
	assert.Equal(t, uint16(0xb7d2), udpHdr.Checksum, "UDP.Checksum")

	// Check Payload
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")
	assert.Equal(t, mkPayload(1024), appLayer.Payload(), "Payload")

}

func TestSerializeSCIONUPDExtn(t *testing.T) {
	s := prepPacket(t, slayers.L4UDP)
	s.NextHdr = slayers.HopByHopClass
	u := &slayers.UDP{}
	u.SrcPort = 1280
	u.DstPort = 80
	u.SetNetworkLayerForChecksum(s)
	hbh := &slayers.HopByHopExtn{}
	hbh.NextHdr = slayers.End2EndClass
	hbh.Options = []*slayers.HopByHopOption{
		(*slayers.HopByHopOption)(&optX),
		(*slayers.HopByHopOption)(&optY),
	}
	e2e := &slayers.EndToEndExtn{}
	e2e.NextHdr = slayers.L4UDP
	e2e.Options = []*slayers.EndToEndOption{
		(*slayers.EndToEndOption)(&optY),
		(*slayers.EndToEndOption)(&optX),
	}
	pld := gopacket.Payload(mkPayload(1024))
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	assert.NoError(t, gopacket.SerializeLayers(b, opts, s, hbh, e2e, u, pld), "Serialize")
	if *update {
		err := os.WriteFile("testdata/"+rawFullPktFilename, b.Bytes(), 0644)
		require.NoError(t, err)
		return
	}
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	assert.Equal(t, raw, b.Bytes(), "Raw buffer")

	// Ensure that the checksum is correct. Calculating over the bytes if the
	// checksum is set should result in 0.
	udpBuf := gopacket.NewSerializeBuffer()
	assert.NoError(t, gopacket.SerializeLayers(udpBuf, opts, u, pld))
	csum := referenceChecksum(append(
		pseudoHeader(t, s, len(udpBuf.Bytes()), 17),
		udpBuf.Bytes()...,
	))
	assert.Zero(t, csum)
}

func TestDecodeSCIONUDPExtn(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")
	// Check that there are exactly 5 layers (SCION, HBH, E2E, SCION/UDP, Payload)
	assert.Equal(t, 5, len(packet.Layers()), "Packet must have 5 layers")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	// Check SCION Header
	assert.Equal(t, uint8(29), s.HdrLen, "HdrLen")
	assert.Equal(t, uint16(1092), s.PayloadLen, "PayloadLen")
	assert.Equal(t, slayers.HopByHopClass, s.NextHdr, "scion.NextHdr")

	// Check H2H Extn
	hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
	require.NotNil(t, hbhL, "HBH layer should exist")
	hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
	assert.Equal(t, slayers.End2EndClass, hbh.NextHdr, "NextHeader")
	assert.Equal(t, uint8(6), hbh.ExtLen, "HBH ExtLen")
	assert.Equal(t, 3, len(hbh.Options), "len(hbh.Options)")
	assert.Equal(t, 28, hbh.ActualLen, "ActualLength")

	// Check E2E Extn
	e2eL := packet.Layer(slayers.LayerTypeEndToEndExtn)
	require.NotNil(t, hbhL, "E2E layer should exist")
	e2e := e2eL.(*slayers.EndToEndExtn) // Guaranteed to work
	assert.Equal(t, slayers.L4UDP, e2e.NextHdr, "NextHeader")
	assert.Equal(t, uint8(7), e2e.ExtLen, "E2E ExtLen")
	assert.Equal(t, 4, len(e2e.Options), "len(hbh.Options)")
	assert.Equal(t, 32, e2e.ActualLen, "ActualLength")

	// Check SCION/UDP Header
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
	assert.Equal(t, uint16(1280), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, uint16(80), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(1032), udpHdr.Length, "UDP.Len")
	assert.Equal(t, uint16(0xb7d2), udpHdr.Checksum, "UDP.Checksum")

	// Check Payload
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")
	assert.Equal(t, mkPayload(1024), appLayer.Payload(), "Payload")
}

func TestPacketDecodeIsInverseOfSerialize(t *testing.T) {
	raw := xtest.MustReadFromFile(t, rawFullPktFilename)
	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	require.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
	require.NotNil(t, hbhL, "HBH layer should exist")
	hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
	e2eL := packet.Layer(slayers.LayerTypeEndToEndExtn)
	require.NotNil(t, hbhL, "E2E layer should exist")
	e2e := e2eL.(*slayers.EndToEndExtn) // Guaranteed to work
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	require.NoError(t, gopacket.SerializeLayers(b, opts, s, hbh, e2e, udpHdr,
		gopacket.Payload(appLayer.Payload())), "Serialize")

	assert.Equal(t, raw, b.Bytes())
}

func BenchmarkDecodeEager(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawUDPPktFilename)

	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	}
}

func BenchmarkDecodeLayerParser(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawUDPPktFilename)
	var scn slayers.SCION
	var hbh slayers.HopByHopExtn
	var e2e slayers.EndToEndExtn
	var udp slayers.UDP
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld,
	)
	decoded := []gopacket.LayerType{}
	for i := 0; i < b.N; i++ {
		if err := parser.DecodeLayers(raw, &decoded); err != nil {
			b.Fatalf("error: %v\n", err)
		}
	}
}

func BenchmarkDecodeLayerParserExtn(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawFullPktFilename)
	var scn slayers.SCION
	var hbh slayers.HopByHopExtn
	var e2e slayers.EndToEndExtn
	var udp slayers.UDP
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld,
	)
	decoded := []gopacket.LayerType{}
	for i := 0; i < b.N; i++ {
		if err := parser.DecodeLayers(raw, &decoded); err != nil {
			b.Fatalf("error: %v\n", err)
		}
	}
}

func BenchmarkDecodeLayerParserExtnSkipper(b *testing.B) {
	raw := xtest.MustReadFromFile(b, rawFullPktFilename)
	var scn slayers.SCION
	var hbh slayers.HopByHopExtnSkipper
	var e2e slayers.EndToEndExtnSkipper
	var udp slayers.UDP
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld,
	)
	decoded := []gopacket.LayerType{}
	for i := 0; i < b.N; i++ {
		if err := parser.DecodeLayers(raw, &decoded); err != nil {
			b.Fatalf("error: %v\n", err)
		}
	}
}

func mkPayload(plen int) []byte {
	b := make([]byte, plen)
	for i := 0; i < plen; i++ {
		b[i] = uint8(i % 256)
	}
	return b
}
