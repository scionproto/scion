// Copyright 2019 Anapaya Systems
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

package trust

import (
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

// ErrRecursionNotAllowed indicates that recursion is not allowed.
var ErrRecursionNotAllowed = serrors.New("recursion not allowed")

// Recurser decides whether a recursive request is permitted for a given peer.
// For infra services use either ASLocalRecurser or LocalOnlyRecurser.
type Recurser interface {
	// AllowRecursion indicates whether the recursion is allowed for the
	// provided Peer. Recursions started by the local trust store have a nil
	// address and should generally be allowed. The nil value indicates
	// recursion is allowed. Non-nil return values indicate that recursion is
	// not allowed and specify the reason.
	AllowRecursion(peer net.Addr) error
}

// ASLocalRecurser allows AS local addresses to start recursive requests.
type ASLocalRecurser struct {
	IA addr.IA
}

// AllowRecursion returns an error if address is not part of the local AS (or if
// the check cannot be made).
func (r ASLocalRecurser) AllowRecursion(peer net.Addr) error {
	if peer == nil {
		return nil
	}
	switch a := peer.(type) {
	case *snet.UDPAddr:
		if !r.IA.Equal(a.IA) {
			return serrors.Wrap("client outside local AS", ErrRecursionNotAllowed,
				"addr", peer)
		}
		return nil
	case *net.TCPAddr:
		// local host is allowed
		return nil
	default:
		return serrors.Wrap("unable to determine AS of peer", ErrRecursionNotAllowed,
			"addr", peer, "type", common.TypeOf(peer))
	}
}

// LocalOnlyRecurser returns an error if the address is not nil.
type LocalOnlyRecurser struct{}

// AllowRecursion returns an error if the address is not nil.
func (r LocalOnlyRecurser) AllowRecursion(peer net.Addr) error {
	if peer != nil {
		return serrors.Wrap("client not host-local", ErrRecursionNotAllowed, "addr", peer)
	}
	return nil
}

type NeverRecurser struct{}

func (r NeverRecurser) AllowRecursion(peer net.Addr) error {
	return serrors.New("recursion never allowed")
}
