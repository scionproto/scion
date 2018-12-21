// Copyright 2018 ETH Zurich
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

// Package network implements the SCION dispatcher dataplane.
package network

import (
	"net"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spkt"
)

// Packet describes a SCION packet. Fields might reference each other
// (including hidden fields), so callers should only write to freshly created
// packets, and readers should take care never to mutate data.
type Packet struct {
	Data          common.RawBytes
	Info          spkt.ScnPkt
	OverlayRemote *net.UDPAddr

	// buffer contains the raw slice that other fields reference
	buffer common.RawBytes
}
