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
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/slayers"
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

func initSPI(t *testing.T) slayers.PacketAuthSPI {
	spi, err := slayers.MakePacketAuthSPIDRKey(
		1,
		slayers.PacketAuthASHost,
		slayers.PacketAuthReceiverSide,
		slayers.PacketAuthLater)
	require.NoError(t, err)
	return spi
}
