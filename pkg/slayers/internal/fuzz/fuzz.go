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

package fuzz

import (
	"bytes"
	"fmt"

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/slayers"
)

// Fuzz fuzzes a SCION packet.
func Fuzz(data []byte) int {
	pkt := gopacket.NewPacket(data, slayers.LayerTypeSCION, gopacket.DecodeOptions{
		NoCopy:             true,
		SkipDecodeRecovery: true,
	})
	for _, l := range pkt.Layers() {
		gopacket.LayerString(l)
	}
	if pkt.ErrorLayer() != nil {
		return 0
	}
	return 1
}

// FuzzLayers is the target that fuzzes all layers. The layer to fuzz is
// determined by the first byte in the input.
func FuzzLayers(data []byte) int {
	targets := []fuzzableLayer{
		&slayers.SCION{},
		&slayers.HopByHopExtn{},
		&slayers.EndToEndExtn{},
		&slayers.UDP{},
		&slayers.SCMP{},
		&slayers.SCMPEcho{},
		&slayers.SCMPTraceroute{},
		&slayers.SCMPExternalInterfaceDown{},
		&slayers.SCMPInternalConnectivityDown{},
	}
	i := int(data[0]) % len(targets)
	return fuzzLayer(targets[i], data[1:])
}

// FuzzSCION is the fuzzing target for the SCION header.
func FuzzSCION(data []byte) int {
	var l slayers.SCION
	return fuzzLayer(&l, data)
}

// FuzzHopByHopExtn is the fuzzing target for the HopByHop extension.
func FuzzHopByHopExtn(data []byte) int {
	var l slayers.HopByHopExtn
	return fuzzLayer(&l, data)
}

// FuzzEndToEndExtn is the fuzzing target for the EndToEnd extension.
func FuzzEndToEndExtn(data []byte) int {
	var l slayers.EndToEndExtn
	return fuzzLayer(&l, data)
}

// FuzzUDP is the fuzzing target for the UDP/SCION header.
func FuzzUDP(data []byte) int {
	var l slayers.SCION
	return fuzzLayer(&l, data)
}

// FuzzSCMP is the fuzzing target for the SCMP header.
func FuzzSCMP(data []byte) int {
	var l slayers.SCMP
	return fuzzLayer(&l, data)
}

// FuzzSCMPEcho is the fuzzing target for SCMP Echo.
func FuzzSCMPEcho(data []byte) int {
	var l slayers.SCMPEcho
	return fuzzLayer(&l, data)
}

// FuzzSCMPTraceroute is the fuzzing target for SCMP Traceroute.
func FuzzSCMPTraceroute(data []byte) int {
	var l slayers.SCMPTraceroute
	return fuzzLayer(&l, data)
}

// FuzzSCMPExternalInterfaceDown is the fuzzing target for SCMP
// ExternalInterfaceDown.
func FuzzSCMPExternalInterfaceDown(data []byte) int {
	var l slayers.SCMPExternalInterfaceDown
	return fuzzLayer(&l, data)
}

// FuzzSCMPInternalConnectivityDown is the fuzzing target for SCMP
// InternalConnectivityDown.
func FuzzSCMPInternalConnectivityDown(data []byte) int {
	var l slayers.SCMPInternalConnectivityDown
	return fuzzLayer(&l, data)
}

type fuzzableLayer interface {
	DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error
	SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error
}

func fuzzLayer(l fuzzableLayer, data []byte) int {
	var feedback fuzzFeedback
	if err := l.DecodeFromBytes(data, &feedback); err != nil {
		return 0
	}
	buf := gopacket.NewSerializeBuffer()
	if err := l.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(fmt.Sprintf("cannot serialize without fix lengths %v", err))
	}
	if !bytes.Equal(buf.Bytes(), data[:len(buf.Bytes())]) {
		panic("serialized data differs without fix lengths")
	}
	// Check that we can fix the length. We do not check the serialized data is
	// the same as the input, as is likely to differ, if the header contains a
	// length fields.
	buf = gopacket.NewSerializeBuffer()
	if err := l.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(fmt.Sprintf("cannot serialize with fix lengths %v", err))
	}
	return 1
}

type fuzzFeedback struct {
	Truncated bool
}

func (f *fuzzFeedback) SetTruncated() {
	f.Truncated = true
}
