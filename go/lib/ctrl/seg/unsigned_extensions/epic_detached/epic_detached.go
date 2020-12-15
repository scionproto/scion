// Copyright 2020 ETH Zurich
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

package epic_detached

import (
	"github.com/scionproto/scion/go/pkg/proto/control_plane/experimental"
)

type Auth []byte

const AuthLen = 10

type EpicDetached struct {
	// The remaining 10 bytes of the hop entry MAC
	AuthHopEntry []byte
	// The remaining 10 bytes of the peer entry MACs
	AuthPeerEntries [][]byte
}

// EpicDetachedFromPB returns the go-representation of the detached Epic extension.
// All the authenticators must be of length AuthLen, otherwise no authenticator
// will be parsed at all.
func EpicDetachedFromPB(ext *experimental.EPICDetachedExtension) *EpicDetached {
	if ext == nil {
		return nil
	}
	if ext.AuthHopEntry == nil || len(ext.AuthHopEntry) != AuthLen {
		return nil
	}
	hop := make([]byte, 10)
	copy(hop, ext.AuthHopEntry)

	peers := make([][]byte, 0, len(ext.AuthPeerEntries))
	for _, p := range ext.AuthPeerEntries {
		if p == nil || len(p) != AuthLen {
			return nil
		}
		peer := make([]byte, AuthLen)
		copy(peer, p)
		peers = append(peers, peer)
	}

	return &EpicDetached{
		AuthHopEntry:    hop,
		AuthPeerEntries: peers,
	}
}

// EpicDetachedFromPB returns the protobuf representation of the detached Epic extension.
// All the authenticators must be of length AuthLen, otherwise no authenticator will be
// parsed at all.
func EpicDetachedToPB(ed *EpicDetached) *experimental.EPICDetachedExtension {
	if ed == nil {
		return nil
	}
	if ed.AuthHopEntry == nil || len(ed.AuthHopEntry) != AuthLen {
		return nil
	}
	hop := make([]byte, 10)
	copy(hop, ed.AuthHopEntry)

	peers := make([][]byte, 0, len(ed.AuthPeerEntries))
	for _, p := range ed.AuthPeerEntries {
		if p == nil || len(p) != AuthLen {
			return nil
		}
		peer := make([]byte, AuthLen)
		copy(peer, p)
		peers = append(peers, peer)
	}

	return &experimental.EPICDetachedExtension{
		AuthHopEntry:    hop,
		AuthPeerEntries: peers,
	}
}
