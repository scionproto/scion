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
	"bytes"
	"encoding/hex"
	"math"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/digest"
	"github.com/scionproto/scion/go/lib/ctrl/seg/unsigned_extensions"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

type ASEntry struct {
	// Signed contains the signed ASentry. It is used for signature input.
	Signed *cryptopb.SignedMessage
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
	// UnsignedExtensions holds all the unsigned beaconing extensions.
	UnsignedExtensions unsigned_extensions.UnsignedExtensions
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

	extensions := ExtensionsFromPB(entry.Extensions)
	unsignedExtensions := unsigned_extensions.UnsignedExtensionsFromPB(pb.Unsigned)
	err = checkUnsignedExtensions(&unsignedExtensions, &extensions)
	if err != nil {
		return ASEntry{}, err
	}

	return ASEntry{
		HopEntry:           hopEntry,
		PeerEntries:        peerEntries,
		Local:              addr.IAInt(entry.IsdAs).IA(),
		Next:               addr.IAInt(entry.NextIsdAs).IA(), // Can contain wildcard.
		MTU:                int(entry.Mtu),
		Extensions:         extensions,
		Signed:             pb.Signed,
		UnsignedExtensions: unsignedExtensions,
	}, nil
}

// checkUnsignedExtensions checks whether the unsigned extensions are consistent with the
// signed hash. Furthermore, an unsigned extension is not valid if it is present in the
// ASEntry, but the corresponding hash is not.
func checkUnsignedExtensions(ue *unsigned_extensions.UnsignedExtensions, e *Extensions) error {
	if ue == nil || e == nil {
		return serrors.New("invalid input to checkUnsignedExtensions")
	}

	// If unsigned extension is present but hash is not, return error
	// EPIC:
	epicDetached := (ue.EpicDetached != nil)
	epicDigest := (e.Digests != nil && len(e.Digests.Epic) != 0)
	if epicDetached && !epicDigest {
		return serrors.New("epic authenticators present, but hash is not")
	}

	// Check consistency (digest extension contains correct hash)
	// EPIC:
	if epicDetached && epicDigest {
		epicDigest, err := digest.CalcEpicDigest(ue.EpicDetached)
		if err != nil {
			return err
		}
		if !bytes.Equal(epicDigest, e.Digests.Epic) {
			return serrors.New("epic authenticators and their hash are not consistent",
				"calculated", hex.EncodeToString(epicDigest), "beacon:",
				hex.EncodeToString(e.Digests.Epic))
		}
	}
	return nil
}
