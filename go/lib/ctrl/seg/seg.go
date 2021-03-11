// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// This file contains the Go representation of a Path Segment

package seg

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/util"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

// Signer signs path segments.
type Signer interface {
	// Sign signs the AS entry and returns the signature meta data.
	Sign(ctx context.Context, msg []byte, associatedData ...[]byte) (*cryptopb.SignedMessage, error)
}

// Verifier verifies path segments.
type Verifier interface {
	// Verify verifies the AS entry based on the signature meta data.
	Verify(ctx context.Context, signedMsg *cryptopb.SignedMessage,
		associatedData ...[]byte) (*signed.Message, error)
}

// ValidationMethod is the method that is used during validation.
type ValidationMethod bool

const (
	// ValidateSegment validates that remote ingress and egress ISD-AS for
	// each AS entry are consistent with the segment. The ingress ISD-AS of
	// the first entry, and the egress ISD-AS of the last entry must be the
	// zero value. Additionally, it is validated that each hop field is
	// parsable.
	ValidateSegment ValidationMethod = false
	// ValidateBeacon validates the segment in the same manner as
	// ValidateSegment, except for the last AS entry. The egress values for
	// the last AS entry are ignored, since they are under construction in
	// a beacon.
	ValidateBeacon ValidationMethod = true
)

type PathSegment struct {
	Info Info
	// ASEntries is the list of AS entries. Call AddASEntry to extend the list.
	ASEntries []ASEntry
}

// CreateSegment creates a new path segment. The AS entries should be added
// using AddASEntry.
func CreateSegment(timestamp time.Time, segID uint16) (*PathSegment, error) {
	info, err := NewInfo(timestamp, segID)
	if err != nil {
		return nil, err
	}
	return &PathSegment{
		Info: info,
	}, nil
}

// SegmentFromPB translates a protobuf path segment.
func SegmentFromPB(pb *cppb.PathSegment) (*PathSegment, error) {
	seg, err := segmentFromPB(pb)
	if err != nil {
		return nil, err
	}
	if err := seg.Validate(ValidateSegment); err != nil {
		return nil, err
	}
	return seg, nil
}

// BeaconFromPB translates a protobuf path Beacon.
func BeaconFromPB(pb *cppb.PathSegment) (*PathSegment, error) {
	seg, err := segmentFromPB(pb)
	if err != nil {
		return nil, err
	}
	if err := seg.Validate(ValidateBeacon); err != nil {
		return nil, err
	}
	return seg, nil
}

func segmentFromPB(pb *cppb.PathSegment) (*PathSegment, error) {
	info, err := infoFromRaw(pb.SegmentInfo)
	if err != nil {
		return nil, serrors.WrapStr("parsing segment info", err)
	}
	asEntries := make([]ASEntry, 0, len(pb.AsEntries))
	for i, entry := range pb.AsEntries {
		as, err := ASEntryFromPB(entry)
		if err != nil {
			return nil, serrors.WrapStr("parsing AS entry", err, "index", i)
		}
		asEntries = append(asEntries, as)
	}
	return &PathSegment{
		ASEntries: asEntries,
		Info:      info,
	}, nil
}

// ID returns a hash of the segment covering all hops, except for peerings.
func (ps *PathSegment) ID() []byte {
	return ps.calculateHash(true)
}

// FullID returns a hash of the segment covering all hops including peerings.
func (ps *PathSegment) FullID() []byte {
	return ps.calculateHash(false)
}

func (ps *PathSegment) calculateHash(hopOnly bool) []byte {
	h := sha256.New()
	for _, ase := range ps.ASEntries {
		binary.Write(h, binary.BigEndian, ase.Local.IAInt())
		binary.Write(h, binary.BigEndian, ase.HopEntry.HopField.ConsIngress)
		binary.Write(h, binary.BigEndian, ase.HopEntry.HopField.ConsEgress)
		if hopOnly {
			continue
		}
		for _, peer := range ase.PeerEntries {
			binary.Write(h, binary.BigEndian, peer.Peer.IAInt())
			binary.Write(h, binary.BigEndian, peer.HopField.ConsIngress)
			binary.Write(h, binary.BigEndian, peer.HopField.ConsEgress)
		}
	}
	return h.Sum(nil)
}

// Validate validates that remote ingress and egress ISD-AS for each AS
// entry are consistent with the segment. In case a beacon is validated,
// the egress ISD-AS of the last AS entry is ignored.
func (ps *PathSegment) Validate(validationMethod ValidationMethod) error {
	if len(ps.ASEntries) == 0 {
		return serrors.New("no AS entries")
	}
	if ingress := ps.ASEntries[0].HopEntry.HopField.ConsIngress; ingress != 0 {
		return serrors.New("first hop with non-zero ingress interface", "ingress_id", ingress)
	}
	for i := range ps.ASEntries {
		next := ps.ASEntries[i].Next
		switch {
		case i < len(ps.ASEntries)-1:
			if nextLocal := ps.ASEntries[i+1].Local; !next.Equal(nextLocal) {
				return serrors.New("next AS entry has inconsistent ISD-AS",
					"curr_entry.next", next, "next_entry.local", nextLocal, "index", i)
			}
		case validationMethod == ValidateBeacon:
			if next.IsWildcard() {
				return serrors.New("next ISD-AS of the last AS entry in a beacon must not be empty")
			}
			if egress := ps.ASEntries[i].HopEntry.HopField.ConsEgress; egress == 0 {
				return serrors.New("last hop in beacon with zero egress interface")
			}
		default:
			if !next.IsZero() {
				return serrors.New("next ISD-AS of last AS entry in a segment must be empty",
					"next", next)
			}
			if egress := ps.ASEntries[i].HopEntry.HopField.ConsEgress; egress != 0 {
				return serrors.New("last hop in segment with non-zero egress interface",
					"egress_id", egress)
			}
		}
		for j, peer := range ps.ASEntries[i].PeerEntries {
			egPeer, egHop := peer.HopField.ConsEgress, ps.ASEntries[i].HopEntry.HopField.ConsEgress
			if egPeer != egHop {
				return serrors.New("egress interface of peer entry does not match hop entry",
					"expected", egHop, "actual", egPeer, "as_entry_idx", i, "peer_entry_idx", j)
			}
		}

		extensions := ps.ASEntries[i].Extensions
		unsignedExtensions := ps.ASEntries[i].UnsignedExtensions
		if err := checkUnsignedExtensions(&unsignedExtensions, &extensions); err != nil {
			return err
		}
	}

	return nil
}

// MaxExpiry returns the maximum expiry of all hop fields.
// Assumes segment is validated.
func (ps *PathSegment) MaxExpiry() time.Time {
	return ps.expiry(0, func(hfTtl time.Duration, ttl time.Duration) bool {
		return hfTtl > ttl
	})
}

// MinExpiry returns the minimum expiry of all hop fields.
// Assumes segment is validated.
func (ps *PathSegment) MinExpiry() time.Time {
	return ps.expiry(path.MaxTTL*time.Second, func(hfTtl time.Duration, ttl time.Duration) bool {
		return hfTtl < ttl
	})
}

func (ps *PathSegment) expiry(initTTL time.Duration,
	compare func(time.Duration, time.Duration) bool) time.Time {

	ttl := initTTL
	for _, asEntry := range ps.ASEntries {
		hfTTL := path.ExpTimeToDuration(asEntry.HopEntry.HopField.ExpTime)
		if compare(hfTTL, ttl) {
			ttl = hfTTL
		}
		for _, peer := range asEntry.PeerEntries {
			hfTTL := path.ExpTimeToDuration(peer.HopField.ExpTime)
			if compare(hfTTL, ttl) {
				ttl = hfTTL
			}
		}
	}
	return ps.Info.Timestamp.Add(ttl)
}

// FirstIA returns the IA of the first ASEntry.
// Note that if the path segment contains no ASEntries this method will panic.
func (ps *PathSegment) FirstIA() addr.IA {
	return ps.ASEntries[0].Local
}

// LastIA returns the IA of the last ASEntry.
// Note that if the path segment contains no ASEntries this method will panic.
func (ps *PathSegment) LastIA() addr.IA {
	return ps.ASEntries[len(ps.ASEntries)-1].Local
}

// AddASEntry adds the AS entry and signs the resulting path segment. The
// signature is created and does not need to be attached to the input AS entry.
func (ps *PathSegment) AddASEntry(ctx context.Context, asEntry ASEntry, signer Signer) error {
	asEntryPB := &cppb.ASEntrySignedBody{
		IsdAs:     uint64(asEntry.Local.IAInt()),
		Mtu:       uint32(asEntry.MTU),
		NextIsdAs: uint64(asEntry.Next.IAInt()),
		HopEntry: &cppb.HopEntry{
			IngressMtu: uint32(asEntry.HopEntry.IngressMTU),
			HopField: &cppb.HopField{
				ExpTime: uint32(asEntry.HopEntry.HopField.ExpTime),
				Ingress: uint64(asEntry.HopEntry.HopField.ConsIngress),
				Egress:  uint64(asEntry.HopEntry.HopField.ConsEgress),
				Mac:     asEntry.HopEntry.HopField.MAC,
			},
		},
		PeerEntries: make([]*cppb.PeerEntry, 0, len(asEntry.PeerEntries)),
		Extensions:  extensionsToPB(asEntry.Extensions),
	}
	for _, peer := range asEntry.PeerEntries {
		asEntryPB.PeerEntries = append(asEntryPB.PeerEntries,
			&cppb.PeerEntry{
				PeerIsdAs:     uint64(peer.Peer.IAInt()),
				PeerInterface: uint64(peer.PeerInterface),
				PeerMtu:       uint32(peer.PeerMTU),
				HopField: &cppb.HopField{
					ExpTime: uint32(peer.HopField.ExpTime),
					Ingress: uint64(peer.HopField.ConsIngress),
					Egress:  uint64(peer.HopField.ConsEgress),
					Mac:     peer.HopField.MAC,
				},
			},
		)
	}
	rawASEntry, err := proto.Marshal(asEntryPB)
	if err != nil {
		return serrors.WrapStr("packing AS entry", err)
	}
	signedMsg, err := signer.Sign(ctx, rawASEntry, ps.associatedData(len(ps.ASEntries))...)
	if err != nil {
		return serrors.WrapStr("signing AS entry", err)
	}
	asEntry.Signed = signedMsg
	ps.ASEntries = append(ps.ASEntries, asEntry)
	return nil
}

// Verify verifies each AS entry.
func (ps *PathSegment) Verify(ctx context.Context, verifier Verifier) error {
	for i := range ps.ASEntries {
		if err := ps.VerifyASEntry(ctx, verifier, i); err != nil {
			return serrors.WrapStr("verifying AS entry", err, "idx", i)
		}
	}
	return nil
}

// VerifyASEntry verifies the AS Entry at the specified index.
func (ps *PathSegment) VerifyASEntry(ctx context.Context, verifier Verifier, idx int) error {
	if err := ps.validateIdx(idx); err != nil {
		return err
	}
	_, err := verifier.Verify(ctx, ps.ASEntries[idx].Signed, ps.associatedData(idx)...)
	return err
}

// associatedData returns the associated data for the AS entry at the given
// index.
func (ps *PathSegment) associatedData(idx int) [][]byte {
	associatedData := make([][]byte, 0, 1+(idx*2))
	associatedData = append(associatedData, ps.Info.Raw)
	for i := 0; i < idx; i++ {
		associatedData = append(associatedData,
			ps.ASEntries[i].Signed.HeaderAndBody,
			ps.ASEntries[i].Signed.Signature,
		)
	}
	return associatedData
}

// MaxIdx returns the index of the last AS entry.
func (ps *PathSegment) MaxIdx() int {
	return len(ps.ASEntries) - 1
}

func (ps *PathSegment) validateIdx(idx int) error {
	if idx < 0 || idx > ps.MaxIdx() {
		return serrors.New("index is out of range", "min", 0, "max", ps.MaxIdx(), "actual", idx)
	}
	return nil
}

// ShallowCopy creates a shallow copy of the path segment.
func (ps *PathSegment) ShallowCopy() *PathSegment {
	if ps == nil {
		return nil
	}
	entries := make([]ASEntry, len(ps.ASEntries))
	copy(entries, ps.ASEntries)
	return &PathSegment{
		Info:      ps.Info,
		ASEntries: entries,
	}
}

// PathSegmentToPB translates a path segment to the protobuf encoding.
func PathSegmentToPB(ps *PathSegment) *cppb.PathSegment {
	if ps == nil {
		panic("path segment must not be nil")
	}
	pb := &cppb.PathSegment{
		SegmentInfo: ps.Info.Raw,
		AsEntries:   make([]*cppb.ASEntry, 0, len(ps.ASEntries)),
	}
	for _, entry := range ps.ASEntries {
		pb.AsEntries = append(pb.AsEntries, &cppb.ASEntry{
			Signed:   entry.Signed,
			Unsigned: UnsignedExtensionsToPB(entry.UnsignedExtensions),
		})
	}
	return pb
}

func (ps *PathSegment) String() string {
	if ps == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ID: %s Timestamp: %s Hops: %s",
		ps.GetLoggingID(),
		util.TimeToCompact(ps.Info.Timestamp),
		ps.getHopsDescription(),
	)
}

func (ps *PathSegment) GetLoggingID() string {
	return fmt.Sprintf("%x", ps.ID()[:12])
}

func (ps *PathSegment) getHopsDescription() string {
	description := []string{}
	for _, as := range ps.ASEntries {
		description = append(description, getHopDescription(as.Local, as.HopEntry.HopField))
	}
	// TODO(shitz): Add extensions.
	return strings.Join(description, ">")
}

func getHopDescription(ia addr.IA, hop HopField) string {
	desc := []string{}
	if hop.ConsIngress > 0 {
		desc = append(desc, fmt.Sprintf("%v ", hop.ConsIngress))
	}
	desc = append(desc, ia.String())
	if hop.ConsEgress > 0 {
		desc = append(desc, fmt.Sprintf(" %v", hop.ConsEgress))
	}
	return strings.Join(desc, "")
}
