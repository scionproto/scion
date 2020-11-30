// Copyright 2017 ETH Zurich
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

// This file contains the Go representation of an AS entry in a path segment

package seg

import (
	"math"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

type ASEntry struct {
	// Signed contains the signed ASentry. It is used for signature input.
	Signed *cryptopb.SignedMessage
	// Unsigned contains the unsigned part of the AS entry.
	Unsigned ASEntryUnsigned
	// Local is the ISD-AS of the AS correspoding to this entry.
	Local addr.IA
	// Next is the ISD-AS of the downstream AS.
	Next addr.IA
	// HopEntry is the entry to create regular data plane paths.
	HopEntry HopEntry
	// PeerEntries is a list of entries to create peering data plane paths.
	PeerEntries []PeerEntry
	// MTU is the AS internal MTU.
	MTU int
	// Extensions holds all the beaconing extensions.
	Extensions Extensions
}

type ASEntryUnsigned struct {
	// EPIC: The remaining 10 bytes of the hop entry MAC
	EpicHopMac []byte
	// EPIC: The remaining 10 bytes of the peer entry MACs
	EpicPeerMacs [][]byte
}

// ASEntryFromPB creates an AS entry from the protobuf representation.
func ASEntryFromPB(pb *cppb.ASEntry) (ASEntry, error) {
	if pb == nil {
		return ASEntry{}, serrors.New("nil entry")
	}
	unverifiedBody, err := signed.ExtractUnverifiedBody(pb.Signed)
	if err != nil {
		return ASEntry{}, err
	}
	var entry cppb.ASEntrySignedBody
	if err := proto.Unmarshal(unverifiedBody, &entry); err != nil {
		return ASEntry{}, err
	}
	if ia := addr.IAInt(entry.IsdAs).IA(); ia.IsWildcard() {
		return ASEntry{}, serrors.New("wildcard local ISD-AS", "isd_as", ia)
	}
	if entry.Mtu > math.MaxInt32 {
		return ASEntry{}, serrors.New("MTU too big", "mtu", entry.Mtu)
	}
	hopEntry, err := hopEntryFromPB(entry.HopEntry)
	if err != nil {
		return ASEntry{}, serrors.WrapStr("parsing hop entry", err)
	}

	var peerEntries []PeerEntry
	if len(entry.PeerEntries) != 0 {
		peerEntries = make([]PeerEntry, 0, len(entry.PeerEntries))
	}
	for i, peer := range entry.PeerEntries {
		if peer == nil {
			continue
		}
		peerEntry, err := peerEntryFromPB(peer)
		if err != nil {
			return ASEntry{}, serrors.WrapStr("parsing peer entry", err, "index", i)
		}
		peerEntries = append(peerEntries, peerEntry)
	}

	extensions := extensionsFromPB(entry.Extensions)

	unsigned, err := unsignedASEntryFromPB(pb.Unsigned, len(entry.PeerEntries))
	if err != nil {
		return ASEntry{}, serrors.WrapStr("parsing unsigned AS entry", err)
	}

	return ASEntry{
		HopEntry:    hopEntry,
		PeerEntries: peerEntries,
		Local:       addr.IAInt(entry.IsdAs).IA(),
		Next:        addr.IAInt(entry.NextIsdAs).IA(), // Can contain wildcard.
		MTU:         int(entry.Mtu),
		Extensions:  extensions,
		Signed:      pb.Signed,
		Unsigned:    unsigned,
	}, nil
}

// Creates the unsigned part of the AS entry from the protobuf representation.
func unsignedASEntryFromPB(pb *cppb.Unsigned, nr_peers int) (ASEntryUnsigned, error) {
	var EpicHopMac []byte
	var EpicPeerMacs [][]byte

	log.Debug("Try to parse unsigned part of AS entry from PB", "peers", nr_peers)

	// Unsigned part must not be nil
	if pb == nil {
		return ASEntryUnsigned{}, serrors.New("unsigned AS entry is nil")
	}
	// Validate EPIC hop entry MAC
	if pb.EpicHopMac == nil {
		return ASEntryUnsigned{}, serrors.New("EPIC MAC of the hop entry is nil")
	}
	if pb.EpicHopMac.EpicMac == nil {
		return ASEntryUnsigned{}, serrors.New("EPIC MAC (bytes) of the hop entry is nil")
	}
	EpicHopMac = pb.EpicHopMac.EpicMac
	if l := len(EpicHopMac); l != 10 && l != 0 {
		return ASEntryUnsigned{}, serrors.New("EPIC hop entry MAC must be 0 or 10 bytes", "len", l)
	}
	// Validate EPIC MACs of peer entries
	if len(pb.EpicPeerMacs) != nr_peers {
		return ASEntryUnsigned{},
			serrors.New("Not the same number of EPIC peer MACs and SCION peer MACs")
	}
	if len(pb.EpicPeerMacs) != 0 {
		EpicPeerMacs = make([][]byte, 0, nr_peers)
	}
	for i, peerMac := range pb.EpicPeerMacs {
		var empty []byte
		if peerMac == nil {
			EpicPeerMacs = append(EpicPeerMacs, empty)
			continue
		}
		if peerMac.EpicMac == nil {
			EpicPeerMacs = append(EpicPeerMacs, empty)
			continue
		}
		if l := len(peerMac.EpicMac); l != 10 && l != 0 {
			return ASEntryUnsigned{},
				serrors.New("EPIC peer entry MAC must be 0 or 10 bytes", "len", l, "index", i)
		}
		EpicPeerMacs = append(EpicPeerMacs, peerMac.EpicMac)
	}
	log.Debug("Successfully parsed unsigned part of AS entry from PB")

	return ASEntryUnsigned{
		EpicHopMac:   EpicHopMac,
		EpicPeerMacs: EpicPeerMacs,
	}, nil
}
