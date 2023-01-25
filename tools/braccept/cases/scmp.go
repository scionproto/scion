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

package cases

import (
	"github.com/google/gopacket"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/tools/braccept/runner"
)

func scmpNormalizePacket(pkt gopacket.Packet) {
	// Apply all the standard normalizations.
	runner.DefaultNormalizePacket(pkt)
	normalizePacketAuthOption(pkt)
}

// normalizePacketAuthOption zeros out the impredictable fields for the runner
// case, i.e. the timestamp, the sequence number and the authenticator which
// includes the previous fields among others.
func normalizePacketAuthOption(pkt gopacket.Packet) {
	e2e := pkt.Layer(slayers.LayerTypeEndToEndExtn)
	if e2e == nil {
		return
	}
	opt, err := e2e.(*slayers.EndToEndExtn).FindOption(slayers.OptTypeAuthenticator)
	if err != nil {
		return
	}
	optAuth, err := slayers.ParsePacketAuthOption(opt)
	if err != nil {
		return
	}
	spi := optAuth.SPI()
	alg := optAuth.Algorithm()
	auth := []byte{0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0}
	_ = optAuth.Reset(slayers.PacketAuthOptionParams{
		SPI:            spi,
		Algorithm:      alg,
		Timestamp:      uint32(0),
		SequenceNumber: uint32(0),
		Auth:           auth,
	})
}

func normalizedSCMPPacketAuthEndToEndExtn() *slayers.EndToEndExtn {
	spi, err := slayers.MakePacketAuthSPIDRKey(
		uint16(drkey.SCMP),
		slayers.PacketAuthASHost,
		slayers.PacketAuthSenderSide,
		slayers.PacketAuthLater,
	)
	if err != nil {
		panic(err)
	}
	packAuthOpt, err := slayers.NewPacketAuthOption(slayers.PacketAuthOptionParams{
		SPI:            spi,
		Algorithm:      slayers.PacketAuthCMAC,
		Timestamp:      uint32(0),
		SequenceNumber: uint32(0),
		Auth:           make([]byte, 16),
	})
	if err != nil {
		panic(err)
	}
	return &slayers.EndToEndExtn{
		Options: []*slayers.EndToEndOption{
			packAuthOpt.EndToEndOption,
		},
	}
}
