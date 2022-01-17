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

package metrics

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/snet"
)

// Namespace is the prometheus namespace.
const Namespace = "trustengine"

// Trust material
const (
	Chain = "chain"
	TRC   = "trc"
)

// Request types
const (
	TRCReq   = "trc_request"
	ChainReq = "chain_request"
)

// Result types
const (
	Success = prom.Success

	ErrInternal = prom.ErrInternal
	ErrParse    = prom.ErrParse
)

// Triggers
const (
	ASInspector = "trc_inspection"
	App         = "application"
)

var (
	// Handler exposes the handler metrics.
	Handler = newHandler()
	// Signer exposes the signer metrics.
	Signer = newSigner()
)

// PeerToLabel converts the peer address to a peer metric label.
func PeerToLabel(peer net.Addr, local addr.IA) string {
	var ia addr.IA
	switch v := peer.(type) {
	case *snet.SVCAddr:
		ia = v.IA
	case *snet.UDPAddr:
		ia = v.IA
	case *net.TCPAddr:
		return infra.PromSrcASLocal
	default:
		return infra.PromSrcUnknown
	}

	switch {
	case ia.Equal(local):
		return infra.PromSrcASLocal
	case ia.ISD() == local.ISD():
		return infra.PromSrcISDLocal
	default:
		return infra.PromSrcISDRemote
	}
}
