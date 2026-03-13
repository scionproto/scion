// Copyright 2026 ETH Zurich
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

package hummingbird

import (
	"github.com/scionproto/scion/pkg/addr"
	hummslayers "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
)

const AkSize = hummslayers.AkBufferSize

type BaseHop struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}

type FlyoverData struct {
	BaseHop

	ResID     uint32       // Unique per AS.
	Ak        [AkSize]byte // Authentication key.
	Bw        uint16
	StartTime uint32 // Unix timestamp for the start of the reservation.
	Duration  uint16 // Duration of the reservation in seconds.
}

// RedemptionRequestNoHop represents the redemption request parameters without ingress or egress.
// It can be used to parametrize a request that will be applied to several hops.
type RedemptionRequestNoHop struct {
	ClientKey    []byte
	IngressToken []byte
	EgressToken  []byte

	BW        uint16
	StartTime uint32
	Duration  uint16
}

// RedemptionRequest contains all the redemption request parameters.
type RedemptionRequest struct {
	RedemptionRequestNoHop
	Ingress uint16
	Egress  uint16
}

type RequestMap map[addr.IA]RedemptionRequest
