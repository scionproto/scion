// Copyright 2020 Anapaya Systems
// Copyright 2025 SCION Association
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

package runner

import (
	"net"

	"github.com/gopacket/gopacket"
)

type NormalizePacketFn func(gopacket.Packet)

// Case represents a border router test case.
type Case struct {
	Name              string
	WriteTo, ReadFrom string
	LocalMAC          net.HardwareAddr
	Input, Want       []byte
	StoreDir          string
	IgnoreNonMatching bool
	// NormalizePacket is a function that will be called both on actual and
	// expected packet. It can modify the packet fields so that unpredictable
	// values are zeroed out and the packets match.
	NormalizePacket NormalizePacketFn
}
