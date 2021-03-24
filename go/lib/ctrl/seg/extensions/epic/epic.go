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

package epic

import (
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/proto/control_plane/experimental"
)

const AuthLen = 10

type Detached struct {
	// The remaining 10 bytes of the hop entry MAC
	AuthHopEntry []byte
	// The remaining 10 bytes of the peer entry MACs
	AuthPeerEntries [][]byte
}

// DetachedFromPB returns the go-representation of the detached Epic extension.
// All the authenticators must be of length AuthLen, otherwise no authenticator
// will be parsed at all.
func DetachedFromPB(ext *experimental.EPICDetachedExtension) *Detached {
	if ext == nil {
		return nil
	}
	hop := make([]byte, AuthLen)
	copy(hop, ext.AuthHopEntry)

	peers := make([][]byte, 0, len(ext.AuthPeerEntries))
	for _, p := range ext.AuthPeerEntries {
		peer := make([]byte, AuthLen)
		copy(peer, p)
		peers = append(peers, peer)
	}

	return &Detached{
		AuthHopEntry:    hop,
		AuthPeerEntries: peers,
	}
}

// DetachedFromPB returns the protobuf representation of the detached Epic extension.
// All the authenticators must be of length AuthLen, otherwise no authenticator will be
// parsed at all.
func DetachedToPB(ed *Detached) *experimental.EPICDetachedExtension {
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

func (ed *Detached) DigestInput() ([]byte, error) {
	if ed == nil {
		return nil, serrors.New("struct Detached pointer must not be nil")
	}
	bufSize := 2 + (1+len(ed.AuthPeerEntries))*AuthLen
	b := make([]byte, bufSize)

	var totalLen uint16 = uint16(1 + len(ed.AuthPeerEntries))
	binary.BigEndian.PutUint16(b, totalLen)

	if len(ed.AuthHopEntry) != AuthLen {
		return nil, serrors.New("hop entry authenticator of wrong length",
			"expected", AuthLen, "actual", len(ed.AuthHopEntry))
	}
	copy(b[2:12], ed.AuthHopEntry)

	offset := 12
	for _, peer := range ed.AuthPeerEntries {
		if len(peer) != AuthLen {
			return nil, serrors.New("peer entry authenticator of wrong length",
				"expected", AuthLen, "actual", len(peer))
		}
		copy(b[offset:offset+AuthLen], peer)
		offset += AuthLen
	}
	return b, nil
}
