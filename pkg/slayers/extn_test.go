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
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/slayers"
)

// Adapted from RFC 8200 Appendix A

// Option X: 4-byte field, followed by 8-byte field. Alignment 8n + 2
var optX = slayers.TLVOption{
	OptType:  0x1e,
	OptData:  []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb},
	OptAlign: [2]uint8{8, 2},
}

// Option Y: 1-byte field, followed by 2-byte field, followed by 4-byte field. Alignment 4n + 3
var optY = slayers.TLVOption{
	OptType:  0x3e,
	OptData:  []byte{0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44},
	OptAlign: [2]uint8{4, 3},
}

// A Hop-by-Hop or EndToEnd Options header containing both options X and Y would have one of the two
// following formats, depending on which option appeared first:
//
//	Option X | Option Y
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Next Header  | Hdr Ext Len=6 | Option Type=X |Opt Data Len=12|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         4-octet field                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	+                         8-octet field                         +
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| PadN Option=1 |Opt Data Len=1 |       0       | Option Type=Y |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Opt Data Len=7 | 1-octet field |         2-octet field         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         4-octet field                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	Option Y | Option X
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Next Header  | Hdr Ext Len=7 | Pad1 Option=0 | Option Type=Y |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Opt Data Len=7 | 1-octet field |         2-octet field         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         4-octet field                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| PadN Option=1 |Opt Data Len=4 |       0       |       0       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|       0       |       0       | Option Type=X |Opt Data Len=12|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         4-octet field                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                                                               |
//	+                         8-octet field                         +
//	|                                                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
var rawTLVOptionsXY = []byte{0x1e, 0x0c, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	0xbb, 0xbb, 0x01, 0x01, 0x00, 0x3e, 0x07, 0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44}
var rawTLVOptionsYX = []byte{0x00, 0x3e, 0x07, 0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44, 0x01, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x1e, 0x0c, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	0xbb, 0xbb}

func TestSerializeTLVOptions(t *testing.T) {
	l := slayers.SerializeTLVOptions(nil, []*slayers.TLVOption{&optX, &optY}, true)
	b := make([]byte, l)
	slayers.SerializeTLVOptions(b, []*slayers.TLVOption{&optX, &optY}, true)
	assert.Equal(t, rawTLVOptionsXY, b, "Serialize OptX|OptY")

	l = slayers.SerializeTLVOptions(nil, []*slayers.TLVOption{&optY, &optX}, true)
	b = make([]byte, l)
	slayers.SerializeTLVOptions(b, []*slayers.TLVOption{&optY, &optX}, true)

	assert.Equal(t, rawTLVOptionsYX, b, "Serialize OptY|OptX")
}

func TestSerializeTLVOptionsWithFinalPadding(t *testing.T) {
	// variable length option test padding after different data lengths
	var optV = slayers.TLVOption{
		OptType:  0x76,
		OptAlign: [2]uint8{1, 0},
		// data filled with repeated 0xff
	}
	ones := [5]byte{0xff, 0xff, 0xff, 0xff, 0xff}

	cases := []struct {
		optLen   int
		expected []byte
	}{
		{
			optLen: 0,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=0 | Option Type=V |Opt Data Len=0 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x00},
		},
		{
			optLen: 1,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=1 | Option Type=V |Opt Data Len=1 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  1-octet data | PadN Option=1 |Opt Data Len=1 |       0       |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x01, 0xff, 0x01, 0x01, 0x00},
		},
		{
			optLen: 2,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=1 | Option Type=V |Opt Data Len=2 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |         2-octet data          | PadN Option=1 |Opt Data Len=0 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x02, 0xff, 0xff, 0x01, 0x00},
		},
		{
			optLen: 3,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=1 | Option Type=V |Opt Data Len=3 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                 3-octet data                  | Pad1 Option=0 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x03, 0xff, 0xff, 0xff, 0x00},
		},
		{
			optLen: 4,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=1 | Option Type=V |Opt Data Len=4 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                          4-octet data                         |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x04, 0xff, 0xff, 0xff, 0xff},
		},
		{
			optLen: 5,
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |  Next Header  | Hdr Ext Len=2 | Option Type=V |Opt Data Len=5 |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |                          5-octet data                         |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// |      ...      | PadN Option=1 |Opt Data Len=1 |       0       |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			expected: []byte{0x76, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0x00},
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("Opt Data Len %d", c.optLen), func(t *testing.T) {
			optV.OptData = ones[:c.optLen]

			l := slayers.SerializeTLVOptions(nil, []*slayers.TLVOption{&optV}, true)
			b := make([]byte, l)
			slayers.SerializeTLVOptions(b, []*slayers.TLVOption{&optV}, true)
			assert.Equal(t, c.expected, b)
		})
	}
}

func TestHopByHopExtnSerialize(t *testing.T) {
	hbh := slayers.HopByHopExtn{}
	hbh.NextHdr = slayers.L4UDP
	hbh.Options = []*slayers.HopByHopOption{
		(*slayers.HopByHopOption)(&optX),
		(*slayers.HopByHopOption)(&optY),
	}
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, hbh.SerializeTo(b, opts), "SerializeTo")
	assert.Equal(t, append([]byte{0x11, 0x06}, rawTLVOptionsXY...), b.Bytes(), "Raw Buffer")
	assert.Equal(t, uint8(6), hbh.ExtLen, "HeaderLength")
}

func TestHopByHopExtnDecode(t *testing.T) {
	raw := append([]byte{0x11, 0x06}, rawTLVOptionsXY...)
	hbh := slayers.HopByHopExtn{}
	assert.NoError(t, hbh.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, slayers.L4UDP, hbh.NextHdr, "NextHeader")
	assert.Equal(t, uint8(6), hbh.ExtLen, "ExtLen")
	assert.Equal(t, 3, len(hbh.Options), "len(hbh.Options)")
	assert.Equal(t, 28, hbh.ActualLen, "ActualLength")
	// First option: Option X
	opt := hbh.Options[0]
	assert.Equal(t, slayers.OptionType(0x1e), opt.OptType, "OptType")
	assert.Equal(t, uint8(12), opt.OptDataLen, "OptLen")
	assert.Equal(t, 14, opt.ActualLength, "ActualLen")
	assert.Equal(t, optX.OptData, opt.OptData, "OptData")
	// Second option: Pad1
	opt = hbh.Options[1]
	assert.Equal(t, slayers.OptTypePadN, opt.OptType, "OptType")
	assert.Equal(t, uint8(1), opt.OptDataLen, "OptLen")
	assert.Equal(t, 3, opt.ActualLength, "ActualLen")
	assert.Equal(t, []byte{0x00}, opt.OptData, "OptData")
	// Third option: Option Y
	opt = hbh.Options[2]
	assert.Equal(t, slayers.OptionType(0x3e), opt.OptType, "OptType")
	assert.Equal(t, uint8(7), opt.OptDataLen, "OptLen")
	assert.Equal(t, 9, opt.ActualLength, "ActualLen")
	assert.Equal(t, optY.OptData, opt.OptData, "OptData")
}

func TestHopByHopExtnDecodeReuse(t *testing.T) {
	raw := append([]byte{0x11, 0x06}, rawTLVOptionsXY...)
	hbh := slayers.HopByHopExtn{}
	// First call to DecodeFromBytes
	assert.NoError(t, hbh.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, len(hbh.Options), 3, "len(hbh.Options)")
	// Second call to decode from bytes; should not preserve the parsed Options
	// from the first call.
	assert.NoError(t, hbh.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, len(hbh.Options), 3, "len(hbh.Options)")
}

func TestHopByHopExtnSerializeDecode(t *testing.T) {
	hbh := slayers.HopByHopExtn{}
	hbh.NextHdr = slayers.L4UDP
	hbh.Options = []*slayers.HopByHopOption{
		(*slayers.HopByHopOption)(&optX),
		(*slayers.HopByHopOption)(&optY),
	}
	// We need to do a first serialization, since the padding options are added on demand on the
	// first serialization.
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	require.NoError(t, hbh.SerializeTo(b, opts))

	// Actual test starts here.
	hbh = slayers.HopByHopExtn{}
	assert.NoError(t, hbh.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	b = gopacket.NewSerializeBuffer()
	assert.NoError(t, hbh.SerializeTo(b, opts))

	got := slayers.HopByHopExtn{}
	assert.NoError(t, got.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	assert.Equal(t, hbh, got)
}

func TestEndToEndExtnSerialize(t *testing.T) {
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = slayers.L4UDP
	e2e.Options = []*slayers.EndToEndOption{
		(*slayers.EndToEndOption)(&optY),
		(*slayers.EndToEndOption)(&optX),
	}
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")
	assert.Equal(t, append([]byte{0x11, 0x07}, rawTLVOptionsYX...), b.Bytes(), "Raw Buffer")
	assert.Equal(t, uint8(7), e2e.ExtLen, "HeaderLength")
}

func TestEndToEndExtnDecode(t *testing.T) {
	raw := append([]byte{0x11, 0x07}, rawTLVOptionsYX...)
	e2e := slayers.EndToEndExtn{}
	assert.NoError(t, e2e.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, slayers.L4UDP, e2e.NextHdr, "NextHeader")
	assert.Equal(t, uint8(7), e2e.ExtLen, "ExtLen")
	assert.Equal(t, 4, len(e2e.Options), "len(e2e.Options)")
	assert.Equal(t, 32, e2e.ActualLen, "ActualLength")
	// First option: Pad1
	opt := e2e.Options[0]
	assert.Equal(t, slayers.OptTypePad1, opt.OptType, "OptType")
	assert.Equal(t, uint8(0), opt.OptDataLen, "OptLen")
	assert.Equal(t, 1, opt.ActualLength, "ActualLen")
	assert.Equal(t, []byte(nil), opt.OptData, "OptData")
	// Second option: Option Y
	opt = e2e.Options[1]
	assert.Equal(t, slayers.OptionType(0x3e), opt.OptType, "OptType")
	assert.Equal(t, uint8(7), opt.OptDataLen, "OptLen")
	assert.Equal(t, 9, opt.ActualLength, "ActualLen")
	assert.Equal(t, optY.OptData, opt.OptData, "OptData")
	// Third option: Pad4
	opt = e2e.Options[2]
	assert.Equal(t, slayers.OptTypePadN, opt.OptType, "OptType")
	assert.Equal(t, uint8(4), opt.OptDataLen, "OptLen")
	assert.Equal(t, 6, opt.ActualLength, "ActualLen")
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, opt.OptData, "OptData")
	// Fourth option: Option X
	opt = e2e.Options[3]
	assert.Equal(t, slayers.OptionType(0x1e), opt.OptType, "OptType")
	assert.Equal(t, uint8(12), opt.OptDataLen, "OptLen")
	assert.Equal(t, 14, opt.ActualLength, "ActualLen")
	assert.Equal(t, optX.OptData, opt.OptData, "OptData")

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: false}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")
	assert.Equal(t, raw, b.Bytes(), "Raw Buffer")
}

func TestEndToEndExtnDecodeReuse(t *testing.T) {
	raw := append([]byte{0x11, 0x07}, rawTLVOptionsYX...)
	e2e := slayers.EndToEndExtn{}
	// First call to DecodeFromBytes
	assert.NoError(t, e2e.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, len(e2e.Options), 4, "len(e2e.Options)")
	// Second call to decode from bytes; should not preserve the parsed Options
	// from the first call.
	assert.NoError(t, e2e.DecodeFromBytes(raw, gopacket.NilDecodeFeedback), "DecodeFromBytes")
	assert.Equal(t, len(e2e.Options), 4, "len(e2e.Options)")
}

func TestEndToEndExtnSerializeDecode(t *testing.T) {
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = slayers.L4UDP
	e2e.Options = []*slayers.EndToEndOption{
		(*slayers.EndToEndOption)(&optY),
		(*slayers.EndToEndOption)(&optX),
	}
	// We need to do a first serialization, since the padding options are added on demand on the
	// first serialization.
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	require.NoError(t, e2e.SerializeTo(b, opts))

	// Actual test starts here.
	e2e = slayers.EndToEndExtn{}
	assert.NoError(t, e2e.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	b = gopacket.NewSerializeBuffer()
	assert.NoError(t, e2e.SerializeTo(b, opts))

	got := slayers.EndToEndExtn{}
	assert.NoError(t, got.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	assert.Equal(t, e2e, got)
}

func TestExtnOrderDecode(t *testing.T) {
	const (
		e2e = slayers.End2EndClass // shorthand
		hbh = slayers.HopByHopClass
	)
	cases := []struct {
		name  string
		extns []slayers.L4ProtocolType
		err   bool
	}{
		{
			name:  "e2e",
			extns: []slayers.L4ProtocolType{e2e},
		},
		{
			name:  "hbh",
			extns: []slayers.L4ProtocolType{hbh},
		},
		{
			name:  "hbh e2e",
			extns: []slayers.L4ProtocolType{hbh, e2e},
		},
		{
			name:  "e2e e2e",
			extns: []slayers.L4ProtocolType{e2e, e2e},
			err:   true, // illegal repetition
		},
		{
			name:  "hbh hbh",
			extns: []slayers.L4ProtocolType{hbh, hbh},
			err:   true, // illegal repetition
		},
		{
			name:  "e2e hbh",
			extns: []slayers.L4ProtocolType{e2e, hbh},
			err:   true, // invalid order
		},
		{
			name:  "hbh e2e e2e",
			extns: []slayers.L4ProtocolType{hbh, e2e, e2e},
			err:   true, // illegal repetition
		},
		{
			name:  "hbh e2e hbh",
			extns: []slayers.L4ProtocolType{hbh, e2e, hbh},
			err:   true, // illegal repetition, invalid order
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("serialize %s", c.name), func(t *testing.T) {
			layers := prepPacketWithExtn(t, c.extns...)
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			err := gopacket.SerializeLayers(buf, opts, layers...)
			if c.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
		t.Run(fmt.Sprintf("decode %s", c.name), func(t *testing.T) {
			raw := prepRawPacketWithExtn(t, c.extns...)
			packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
			if c.err {
				assert.NotNil(t, packet.ErrorLayer())
			} else if packet.ErrorLayer() != nil {
				assert.NoError(t, packet.ErrorLayer().Error())
			}
		})
		t.Run(fmt.Sprintf("decode skip %s", c.name), func(t *testing.T) {
			raw := prepRawPacketWithExtn(t, c.extns...)
			var (
				scn slayers.SCION
				e2e slayers.EndToEndExtnSkipper
				hbh slayers.HopByHopExtnSkipper
				udp slayers.UDP
				pld gopacket.Payload
			)
			parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION,
				&scn, &e2e, &hbh, &udp, &pld,
			)
			decoded := []gopacket.LayerType{}
			err := parser.DecodeLayers(raw, &decoded)
			if c.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtnSkipDecode(t *testing.T) {
	cases := []struct {
		name string
		hbh  bool
		e2e  bool
	}{
		{
			name: "none",
		},
		{
			name: "e2e",
			e2e:  true,
		},
		{
			name: "hbh",
			hbh:  true,
		},
		{
			name: "hbh e2e",
			e2e:  true,
			hbh:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			extns := []slayers.L4ProtocolType{}
			if c.hbh {
				extns = append(extns, slayers.HopByHopClass)
			}
			if c.e2e {
				extns = append(extns, slayers.End2EndClass)
			}
			raw := prepRawPacketWithExtn(t, extns...)
			var (
				scn slayers.SCION
				e2e slayers.EndToEndExtnSkipper
				hbh slayers.HopByHopExtnSkipper
				udp slayers.UDP
				pld gopacket.Payload
			)
			parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION,
				&scn, &e2e, &hbh, &udp, &pld,
			)
			decoded := []gopacket.LayerType{}
			err := parser.DecodeLayers(raw, &decoded)
			require.NoError(t, err)

			// decoded should be: SCION, the expected extension headers, and the UDP + payload
			expected := []gopacket.LayerType{slayers.LayerTypeSCION}
			if c.hbh {
				expected = append(expected, slayers.LayerTypeHopByHopExtn)
			}
			if c.e2e {
				expected = append(expected, slayers.LayerTypeEndToEndExtn)
			}
			expected = append(expected, slayers.LayerTypeSCIONUDP)
			expected = append(expected, gopacket.LayerTypePayload)
			assert.Equal(t, expected, decoded)

			// check that the skipper "captured" the expected part of the packet
			if c.hbh {
				assert.Equal(t, hbh.Contents[2:], rawTLVOptionsXY)
			}
			if c.e2e {
				assert.Equal(t, e2e.Contents[2:], rawTLVOptionsXY)
			}
		})
	}
}

// prepPacketWithExtn creates a (potentially invalid) list of SCION packet layers
// with extension layers in the given order.
func prepPacketWithExtn(t *testing.T,
	extns ...slayers.L4ProtocolType) []gopacket.SerializableLayer {

	scn := prepPacket(t, extns[0])
	layers := []gopacket.SerializableLayer{scn}
	for i, e := range extns {
		next := slayers.L4UDP
		if i+1 < len(extns) {
			next = extns[i+1]
		}
		switch e {
		case slayers.End2EndClass:
			extn := &slayers.EndToEndExtn{}
			extn.NextHdr = next
			layers = append(layers, extn)
		case slayers.HopByHopClass:
			extn := &slayers.HopByHopExtn{}
			extn.NextHdr = next
			layers = append(layers, extn)
		}
	}
	return layers
}

// prepRawPacketWithExtn creates a (potentially invalid) raw SCION packet with
// extensions in the given order.
func prepRawPacketWithExtn(t *testing.T, extns ...slayers.L4ProtocolType) []byte {
	t.Helper()

	first := slayers.L4UDP
	if len(extns) > 0 {
		first = extns[0]
	}
	scn := prepPacket(t, first)
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, scn.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}))

	// Create fake extension headers manually; the extension layers' Serialize
	// logic checks for the correct ordering of the extensions, but we want to
	// create packets with bad order.
	for i := range extns {
		b, err := buf.AppendBytes(2 + len(rawTLVOptionsXY))
		require.NoError(t, err)
		next := slayers.L4UDP
		if i+1 < len(extns) {
			next = extns[i+1]
		}
		b[0] = uint8(next)
		b[1] = 6 // ExtLen, see rawTLVOptionsXY
		copy(b[2:], rawTLVOptionsXY)
	}
	buf.AppendBytes(9) // dummy UDP with 1 byte payload

	return buf.Bytes()
}
