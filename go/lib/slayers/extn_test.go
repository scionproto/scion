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
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/slayers"
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
//   Option X | Option Y
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Next Header  | Hdr Ext Len=6 | Option Type=X |Opt Data Len=12|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         4-octet field                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                         8-octet field                         +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | PadN Option=1 |Opt Data Len=1 |       0       | Option Type=Y |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Opt Data Len=7 | 1-octet field |         2-octet field         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         4-octet field                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Option Y | Option X
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Next Header  | Hdr Ext Len=7 | Pad1 Option=0 | Option Type=Y |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Opt Data Len=7 | 1-octet field |         2-octet field         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         4-octet field                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | PadN Option=1 |Opt Data Len=4 |       0       |       0       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       0       |       0       | Option Type=X |Opt Data Len=12|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                         4-octet field                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                         8-octet field                         +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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

func TestHopByHopExtnSerialize(t *testing.T) {
	hbh := slayers.HopByHopExtn{}
	hbh.NextHdr = common.L4UDP
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
	assert.Equal(t, common.L4UDP, hbh.NextHdr, "NextHeader")
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

func TestHopByHopExtnSerializeDecode(t *testing.T) {
	hbh := slayers.HopByHopExtn{}
	hbh.NextHdr = common.L4UDP
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
	e2e.NextHdr = common.L4UDP
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
	assert.Equal(t, common.L4UDP, e2e.NextHdr, "NextHeader")
	assert.Equal(t, uint8(7), e2e.ExtLen, "ExtLen")
	assert.Equal(t, 4, len(e2e.Options), "len(e2e.Options)")
	assert.Equal(t, 32, e2e.ActualLen, "ActualLength")
	// First option: Pad1
	opt := e2e.Options[0]
	assert.Equal(t, slayers.OptTypePad1, opt.OptType, "OptType")
	assert.Equal(t, uint8(0), opt.OptDataLen, "OptLen")
	assert.Equal(t, 1, opt.ActualLength, "ActualLen")
	assert.Equal(t, []byte(nil), opt.OptData, "OptData")
	// First option: Option Y
	opt = e2e.Options[1]
	assert.Equal(t, slayers.OptionType(0x3e), opt.OptType, "OptType")
	assert.Equal(t, uint8(7), opt.OptDataLen, "OptLen")
	assert.Equal(t, 9, opt.ActualLength, "ActualLen")
	assert.Equal(t, optY.OptData, opt.OptData, "OptData")
	// Second option: Pad4
	opt = e2e.Options[2]
	assert.Equal(t, slayers.OptTypePadN, opt.OptType, "OptType")
	assert.Equal(t, uint8(4), opt.OptDataLen, "OptLen")
	assert.Equal(t, 6, opt.ActualLength, "ActualLen")
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, opt.OptData, "OptData")
	// Third option: Option X
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

func TestEndToEndExtnSerializeDecode(t *testing.T) {
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = common.L4UDP
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

var optAuthMAC = []byte("16byte_mac_foooo")

//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Next Header=UDP| Hdr Ext Len=5 | PadN Option=1 |Opt Data Len=1 |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       0       | Auth Option=2 |Opt Data Len=17| Algo = CMAC   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                        16-octet MAC data                      +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
var rawE2EOptAuth = append(
	[]byte{
		0x11, 0x05, 0x01, 0x01,
		0x0, 0x2, 0x11, 0x0,
	},
	optAuthMAC...,
)

func TestOptAuthenticatorSerialize(t *testing.T) {
	optAuth := slayers.NewPacketAuthenticatorOption(slayers.PacketAuthCMAC, optAuthMAC)

	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = common.L4UDP
	e2e.Options = []*slayers.EndToEndOption{optAuth.EndToEndOption}

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")

	assert.Equal(t, rawE2EOptAuth, b.Bytes(), "Raw Buffer")
}

func TestOptAuthenticatorDeserialize(t *testing.T) {
	e2e := slayers.EndToEndExtn{}

	_, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	assert.Error(t, err)

	assert.NoError(t, e2e.DecodeFromBytes(rawE2EOptAuth, gopacket.NilDecodeFeedback))
	assert.Equal(t, common.L4UDP, e2e.NextHdr, "NextHeader")
	optAuth, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	require.NoError(t, err, "FindOption")
	auth, err := slayers.ParsePacketAuthenticatorOption(optAuth)
	require.NoError(t, err, "ParsePacketAuthenticatorOption")
	assert.Equal(t, slayers.PacketAuthCMAC, auth.Algorithm(), "Algorithm Type")
	assert.Equal(t, optAuthMAC, auth.Authenticator(), "Authenticator data (MAC)")
}

func TestOptAuthenticatorDeserializeCorrupt(t *testing.T) {
	optAuthCorrupt := slayers.EndToEndOption{
		OptType: slayers.OptTypeAuthenticator,
		OptData: []byte{},
	}
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = common.L4UDP
	e2e.Options = []*slayers.EndToEndOption{&optAuthCorrupt}

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")

	assert.NoError(t, e2e.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	optAuth, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	require.NoError(t, err, "FindOption")
	_, err = slayers.ParsePacketAuthenticatorOption(optAuth)
	require.Error(t, err, "ParsePacketAuthenticatorOption should fail")
}
