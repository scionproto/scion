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

package slayers_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

var (
	algo       = slayers.PacketAuthSHA1_AES_CBC
	ts         = binary.LittleEndian.Uint32([]byte{1, 2, 3, 0})
	sn         = binary.LittleEndian.Uint32([]byte{4, 5, 6, 0})
	optAuthMAC = []byte("16byte_mac_foooo")
)

var rawE2EOptAuth = append(
	[]byte{
		0x11, 0x7, 0x2, 0x1c,
		0x0, 0x2, 0x0, 0x1,
		0x1, 0x3, 0x2, 0x1,
		0x0, 0x6, 0x5, 0x4,
	},
	optAuthMAC...,
)

func TestOptAuthenticatorSerialize(t *testing.T) {
	cases := []struct {
		name      string
		spiFunc   func(t *testing.T) slayers.PacketAuthSPI
		algo      slayers.PacketAuthAlg
		ts        uint32
		sn        uint32
		optAuth   []byte
		errorFunc assert.ErrorAssertionFunc
	}{
		{
			name:      "correct",
			spiFunc:   initSPI,
			algo:      algo,
			ts:        ts,
			sn:        sn,
			optAuth:   optAuthMAC,
			errorFunc: assert.NoError,
		},
		{
			name:      "bad_ts",
			spiFunc:   initSPI,
			algo:      algo,
			ts:        binary.LittleEndian.Uint32([]byte{0, 0, 0, 1}),
			sn:        sn,
			optAuth:   optAuthMAC,
			errorFunc: assert.Error,
		},
		{
			name:      "bad_sn",
			spiFunc:   initSPI,
			algo:      algo,
			ts:        ts,
			sn:        binary.LittleEndian.Uint32([]byte{0, 0, 0, 1}),
			optAuth:   optAuthMAC,
			errorFunc: assert.Error,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			spao, err := slayers.NewPacketAuthOption(slayers.PacketAuthOptionParams{
				SPI:            c.spiFunc(t),
				Algorithm:      c.algo,
				Timestamp:      c.ts,
				SequenceNumber: c.sn,
				Auth:           c.optAuth,
			})
			c.errorFunc(t, err)
			if err != nil {
				return
			}

			e2e := slayers.EndToEndExtn{}
			e2e.NextHdr = slayers.L4UDP
			e2e.Options = []*slayers.EndToEndOption{spao.EndToEndOption}

			b := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")
			assert.Equal(t, rawE2EOptAuth, b.Bytes(), "Raw Buffer")
		})
	}
}

func TestOptAuthenticatorDeserialize(t *testing.T) {
	e2e := slayers.EndToEndExtn{}

	_, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	assert.Error(t, err)

	assert.NoError(t, e2e.DecodeFromBytes(rawE2EOptAuth, gopacket.NilDecodeFeedback))
	assert.Equal(t, slayers.L4UDP, e2e.NextHdr, "NextHeader")
	optAuth, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	require.NoError(t, err, "FindOption")
	auth, err := slayers.ParsePacketAuthOption(optAuth)
	require.NoError(t, err, "ParsePacketAuthOption")
	assert.Equal(t, initSPI(t), auth.SPI(), "SPI")
	assert.Equal(t, slayers.PacketAuthASHost, auth.SPI().Type())
	assert.Equal(t, slayers.PacketAuthReceiverSide, auth.SPI().Direction())
	assert.Equal(t, slayers.PacketAuthLater, auth.SPI().Epoch())
	assert.Equal(t, true, auth.SPI().IsDRKey())
	assert.Equal(t, algo, auth.Algorithm(), "Algorithm Type")
	assert.Equal(t, ts, auth.Timestamp(), "Timestamp")
	assert.Equal(t, sn, auth.SequenceNumber(), "Sequence Number")
	assert.Equal(t, optAuthMAC, auth.Authenticator(), "Authenticator data (MAC)")
}

func TestMakePacketAuthSPIDrkey(t *testing.T) {
	spi := initSPI(t)
	assert.EqualValues(t, binary.BigEndian.Uint32([]byte{0, 2, 0, 1}), spi)
}

func TestOptAuthenticatorDeserializeCorrupt(t *testing.T) {
	optAuthCorrupt := slayers.EndToEndOption{
		OptType: slayers.OptTypeAuthenticator,
		OptData: []byte{},
	}
	e2e := slayers.EndToEndExtn{}
	e2e.NextHdr = slayers.L4UDP
	e2e.Options = []*slayers.EndToEndOption{&optAuthCorrupt}

	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	assert.NoError(t, e2e.SerializeTo(b, opts), "SerializeTo")

	assert.NoError(t, e2e.DecodeFromBytes(b.Bytes(), gopacket.NilDecodeFeedback))
	optAuth, err := e2e.FindOption(slayers.OptTypeAuthenticator)
	require.NoError(t, err, "FindOption")
	_, err = slayers.ParsePacketAuthOption(optAuth)
	require.Error(t, err, "ParsePacketAuthOption should fail")
}

func TestComputeAuthMac(t *testing.T) {
	now := time.Unix(0, 0)
	srcIA := xtest.MustParseIA("1-ff00:0:111")
	dstIA := xtest.MustParseIA("1-ff00:0:112")
	macBuff := make([]byte, path.MACBufferSize)

	decodedPath := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]byte{1, 1, 1},
			},
			NumINF:  3,
			NumHops: 3,
		},
		InfoFields: []path.InfoField{
			{
				ConsDir:   false,
				SegID:     1,
				Timestamp: util.TimeToSecs(now),
			},
			{
				ConsDir:   false,
				SegID:     2,
				Timestamp: util.TimeToSecs(now),
			},
			{
				ConsDir:   true,
				SegID:     3,
				Timestamp: util.TimeToSecs(now),
			},
		},
		HopFields: []path.HopField{
			{
				ExpTime:     63,
				ConsIngress: 1,
				ConsEgress:  0,
				Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
			{
				ExpTime:     63,
				ConsIngress: 3,
				ConsEgress:  2,
				Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
			{
				ExpTime:     63,
				ConsIngress: 0,
				ConsEgress:  2,
				Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
			},
		},
	}
	rawPath := make([]byte, decodedPath.Len())
	err := decodedPath.SerializeTo(rawPath)
	require.NoError(t, err)

	testCases := map[string]struct {
		input           []byte
		scionL          slayers.SCION
		pld             []byte
		assertFormatErr assert.ErrorAssertionFunc
	}{
		"decoded": {
			input: make([]byte, slayers.MACBufferSize),
			scionL: slayers.SCION{
				NextHdr:     slayers.End2EndClass,
				SrcIA:       srcIA,
				DstIA:       dstIA,
				DstAddrLen:  slayers.AddrLen4,
				DstAddrType: slayers.T4Ip,
				RawDstAddr:  net.IPv4(192, 0, 0, 1),
				Path:        decodedPath,
			},
			pld:             []byte("some payload"),
			assertFormatErr: assert.NoError,
		},
		"one hop": {
			input: make([]byte, slayers.MACBufferSize),
			scionL: slayers.SCION{
				NextHdr:     slayers.End2EndClass,
				SrcIA:       srcIA,
				DstIA:       dstIA,
				DstAddrLen:  slayers.AddrLen4,
				DstAddrType: slayers.T4Ip,
				RawDstAddr:  net.IPv4(192, 0, 0, 1),
				Path: &onehop.Path{
					Info: path.InfoField{
						ConsDir:   false,
						SegID:     1,
						Timestamp: util.TimeToSecs(now),
					},

					FirstHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 1,
						ConsEgress:  0,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
					SecondHop: path.HopField{
						ExpTime:     63,
						ConsIngress: 3,
						ConsEgress:  2,
						Mac:         [path.MacLen]byte{1, 2, 3, 4, 5, 6},
					},
				},
			},
			pld:             []byte("some payload"),
			assertFormatErr: assert.NoError,
		},
		"epic": {
			input: make([]byte, slayers.MACBufferSize),
			scionL: slayers.SCION{
				NextHdr:     slayers.End2EndClass,
				SrcIA:       srcIA,
				DstIA:       dstIA,
				DstAddrLen:  slayers.AddrLen4,
				DstAddrType: slayers.T4Ip,
				RawDstAddr:  net.IPv4(192, 0, 0, 1),
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
			pld:             []byte("some payload"),
			assertFormatErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {

			dstAddr, err := tc.scionL.DstAddr()
			require.NoError(t, err)
			spao, key := getSPAO(t, tc.scionL.Path, tc.scionL.DstIA, dstAddr.String(), now)
			mac, err := slayers.ComputeAuthCMAC(
				tc.input,
				key[:],
				&tc.scionL,
				spao,
				tc.pld,
				macBuff,
			)
			tc.assertFormatErr(t, err)
			if err != nil {
				return
			}
			goldenFile := "testdata/" + xtest.SanitizedName(t)
			if *update {
				macStr := hex.EncodeToString(mac)
				require.NoError(t, os.WriteFile(goldenFile, []byte(macStr), 0666))
			}
			goldenRaw, err := os.ReadFile(goldenFile)
			require.NoError(t, err)

			goldenMac, err := hex.DecodeString(string(goldenRaw))
			require.NoError(t, err)
			require.Equal(t, goldenMac, mac)
		})
	}
}
func initSPI(t *testing.T) slayers.PacketAuthSPI {
	spi, err := slayers.MakePacketAuthSPIDRKey(
		1,
		slayers.PacketAuthASHost,
		slayers.PacketAuthReceiverSide,
		slayers.PacketAuthLater)
	require.NoError(t, err)
	return spi
}

func getSPAO(
	t *testing.T,
	packetPath path.Path,
	dstIA addr.IA,
	dstHost string,
	now time.Time,
) (
	slayers.PacketAuthOption,
	drkey.Key,
) {

	macBuf := make([]byte, 16)
	dir := slayers.PacketAuthSenderSide
	epoch := slayers.PacketAuthLater
	drkeyType := slayers.PacketAuthASHost

	spi, err := slayers.MakePacketAuthSPIDRKey(uint16(drkey.SCMP), drkeyType, dir, epoch)
	assert.NoError(t, err)

	var firstInfo path.InfoField
	switch p := packetPath.(type) {
	case *scion.Raw:
		firstInfo, err = p.GetInfoField(0)
		require.NoError(t, err)
	case *scion.Decoded:
		firstInfo = p.InfoFields[0]
	case *epic.Path:
		firstInfo, err = p.ScionPath.GetInfoField(0)
		require.NoError(t, err)
	case *onehop.Path:
		firstInfo = p.Info
	default:
		panic(fmt.Sprintf("unknown path type %T", packetPath))
	}

	timestamp, err := slayers.ComputeSPAORelativeTimestamp(firstInfo.Timestamp, now)
	assert.NoError(t, err)

	sn := uint32(0)
	optAuth, err := slayers.NewPacketAuthOption(slayers.PacketAuthOptionParams{
		SPI:            spi,
		Algorithm:      slayers.PacketAuthCMAC,
		Timestamp:      timestamp,
		SequenceNumber: sn,
		Auth:           macBuf,
	})
	assert.NoError(t, err)

	return optAuth, drkey.Key{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
}
