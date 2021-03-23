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
const Namespace = "renewal"

// Signer exposes the signer metrics.
var Signer = newSigner()

const (
	ChainRenewalReq = "chain_renewal_request"
)

// Result types
const (
	Success = prom.Success

	ErrBadRequest  = "err_bad_request"
	ErrDB          = prom.ErrDB
	ErrInactive    = "err_inactive"
	ErrInternal    = prom.ErrInternal
	ErrKey         = "err_key"
	ErrCerts       = "err_certs"
	ErrNotFound    = "err_not_found"
	ErrParse       = prom.ErrParse
	ErrUnavailable = "err_unavailable"
	ErrVerify      = prom.ErrVerify
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
	case ia.I == local.I:
		return infra.PromSrcISDLocal
	default:
		return infra.PromSrcISDRemote
	}
}
