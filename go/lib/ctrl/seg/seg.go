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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// Signer signs path segments.
type Signer interface {
	// Sign signs the packed segment and returns the signature meta data.
	Sign(ctx context.Context, packedSegment []byte) (*proto.SignS, error)
}

// Verifier verifies path segments.
type Verifier interface {
	// Verify verifies the packed segment based on the signature meta data.
	Verify(ctx context.Context, packedSegment []byte, sign *proto.SignS) error
}

var _ proto.Cerealizable = (*Beacon)(nil)

// Beacon is kept for compatibility with python code.
// Before using the enclosed segment, the beacon should be parsed.
type Beacon struct {
	Segment *PathSegment `capnp:"pathSeg"`
}

// Parse parses and validates the enclosed path segment.
func (b *Beacon) Parse() error {
	if b.Segment == nil {
		return serrors.New("Beacon does not contain a segment")
	}
	return b.Segment.ParseRaw(ValidateBeacon)
}

func (b *Beacon) ProtoId() proto.ProtoIdType {
	return proto.PCB_TypeID
}

func (b *Beacon) String() string {
	if b == nil {
		return "<nil>"
	}
	return b.Segment.String()
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

var _ proto.Cerealizable = (*PathSegment)(nil)

type PathSegment struct {
	RawSData     []byte                 `capnp:"sdata"`
	SData        *PathSegmentSignedData `capnp:"-"`
	RawASEntries []*proto.SignedBlobS   `capnp:"asEntries"`
	// ASEntries contains the AS entries.
	// WARNING: Should never be modified! Use AddASEntry or create a new Segment instead.
	ASEntries []*ASEntry `capnp:"-"`
}

// NewSeg creates a new path segment with the specified info field. The AS
// entries are empty and should be added using AddASEntry.
func NewSeg(pss *PathSegmentSignedData) (*PathSegment, error) {
	rawPss, err := proto.PackRoot(pss)
	if err != nil {
		return nil, err
	}
	ps := &PathSegment{RawSData: rawPss, SData: pss}
	return ps, nil
}

// NewSegFromRaw creates a segment from raw data.
func NewSegFromRaw(b []byte) (*PathSegment, error) {
	return newSegFromRaw(b, ValidateSegment)
}

// NewBeaconFromRaw creates a segment from raw data. The last AS entry is
// not assumed to terminate the path segment.
func NewBeaconFromRaw(b []byte) (*PathSegment, error) {
	return newSegFromRaw(b, ValidateBeacon)
}

func newSegFromRaw(b []byte, validationMethod ValidationMethod) (*PathSegment, error) {
	ps := &PathSegment{}
	err := proto.ParseFromRaw(ps, b)
	if err != nil {
		return nil, err
	}
	return ps, ps.ParseRaw(validationMethod)
}

func (ps *PathSegment) ParseRaw(validationMethod ValidationMethod) error {
	var err error
	ps.SData, err = NewPathSegmentSignedDataFromRaw(ps.RawSData)
	if err != nil {
		return err
	}

	ps.ASEntries = make([]*ASEntry, len(ps.RawASEntries))
	for i, rawASEntry := range ps.RawASEntries {
		ps.ASEntries[i], err = NewASEntryFromRaw(rawASEntry.Blob)
		if err != nil {
			return err
		}
	}
	return ps.Validate(validationMethod)
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
		binary.Write(h, binary.BigEndian, ase.RawIA)
		for _, hopE := range ase.HopEntries {
			binary.Write(h, binary.BigEndian, hopE.HopField.ConsIngress)
			binary.Write(h, binary.BigEndian, hopE.HopField.ConsEgress)
			if hopOnly {
				break
			}
		}
	}
	return h.Sum(nil)
}

func (ps *PathSegment) Timestamp() time.Time {
	return util.SecsToTime(ps.SData.RawTimestamp)
}

// Validate validates that remote ingress and egress ISD-AS for each AS
// entry are consistent with the segment. In case a beacon is validated,
// the egress ISD-AS of the last AS entry is ignored.
func (ps *PathSegment) Validate(validationMethod ValidationMethod) error {
	if err := ps.SData.Validate(); err != nil {
		return err
	}
	if len(ps.RawASEntries) == 0 {
		return serrors.New("PathSegment has no AS Entries")
	}
	if len(ps.ASEntries) != len(ps.RawASEntries) {
		return common.NewBasicError(
			"PathSegment has mismatched number of raw and parsed AS Entries", nil,
			"ASEntries", len(ps.ASEntries), "RawASEntries", len(ps.RawASEntries),
		)
	}
	for i := range ps.ASEntries {
		prevIA := addr.IA{}
		nextIA := addr.IA{}
		if i > 0 {
			prevIA = ps.ASEntries[i-1].IA()
		}
		if i < len(ps.ASEntries)-1 {
			nextIA = ps.ASEntries[i+1].IA()
		}
		// The last AS entry in a beacon should ignore whether the next IA
		// matches, since it is not set yet.
		ignoreNext := i == len(ps.ASEntries)-1 && (validationMethod == ValidateBeacon)
		if err := ps.ASEntries[i].Validate(prevIA, nextIA, ignoreNext); err != nil {
			return common.NewBasicError("Unable to validate AS entry", err, "ASEntryIdx", i)
		}
	}
	return nil
}

func (ps *PathSegment) ContainsInterface(ia addr.IA, ifid common.IFIDType) bool {
	for _, asEntry := range ps.ASEntries {
		for _, entry := range asEntry.HopEntries {
			hf, ifid := entry.HopField, uint16(ifid)
			if asEntry.IA().Equal(ia) && (hf.ConsEgress == ifid || hf.ConsIngress == ifid) {
				return true
			}
		}
	}
	return false
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
	return ps.expiry(spath.MaxTTL*time.Second, func(hfTtl time.Duration, ttl time.Duration) bool {
		return hfTtl < ttl
	})
}

func (ps *PathSegment) expiry(initTtl time.Duration,
	compare func(time.Duration, time.Duration) bool) time.Time {

	ttl := initTtl
	for _, asEntry := range ps.ASEntries {
		for _, he := range asEntry.HopEntries {
			hfTTL := spath.ExpTimeType(he.HopField.ExpTime).ToDuration()
			if compare(hfTTL, ttl) {
				ttl = hfTTL
			}
		}
	}
	return ps.Timestamp().Add(ttl)
}

// FirstIA returns the IA of the first ASEntry.
// Note that if the seg contains no ASEntries this method will panic.
func (ps *PathSegment) FirstIA() addr.IA {
	return ps.ASEntries[0].IA()
}

// LastIA returns the IA of the last ASEntry.
// Note that if the seg contains no ASEntries this method will panic.
func (ps *PathSegment) LastIA() addr.IA {
	return ps.ASEntries[len(ps.ASEntries)-1].IA()
}

// WalkHopEntries iterates through the hop entries of asEntries, checking that
// the hop fields within can be parsed. If an parse error is found, the
// function immediately returns with an error.
//
// Deprecated: This will no longer be needed with the header redesign.
func (ps *PathSegment) WalkHopEntries() error {
	for _, asEntry := range ps.ASEntries {
		for _, hopEntry := range asEntry.HopEntries {
			if len(hopEntry.RawHopField) != 0 {
				_, err := spath.HopFFromRaw(hopEntry.RawHopField)
				if err != nil {
					return common.NewBasicError("invalid hop field found in ASEntry",
						err, "asEntry", asEntry)
				}
			}
		}
	}
	return nil
}

// AddASEntry adds the AS entry and signs the resulting path segment.
func (ps *PathSegment) AddASEntry(ctx context.Context, ase *ASEntry, signer Signer) error {
	rawASE, err := ase.Pack()
	if err != nil {
		return err
	}
	ps.RawASEntries = append(ps.RawASEntries, &proto.SignedBlobS{Blob: rawASE})
	ps.ASEntries = append(ps.ASEntries, ase)
	ps.RawASEntries[ps.MaxAEIdx()].Sign, err = signer.Sign(ctx,
		ps.sigPack(ps.MaxAEIdx()))
	if err != nil {
		ps.popLastEntry()
		return err
	}
	return nil
}

func (ps *PathSegment) popLastEntry() {
	ps.RawASEntries = ps.RawASEntries[:len(ps.RawASEntries)-1]
	ps.ASEntries = ps.ASEntries[:len(ps.ASEntries)-1]
}

// VerifyASEntry verifies the AS Entry at the specified index.
func (ps *PathSegment) VerifyASEntry(ctx context.Context, verifier Verifier, idx int) error {
	if err := ps.validateIdx(idx); err != nil {
		return err
	}
	return verifier.Verify(ctx, ps.sigPack(idx), ps.RawASEntries[idx].Sign)
}

func (ps *PathSegment) sigPack(idx int) common.RawBytes {
	data := append(common.RawBytes(nil), ps.RawSData...)
	for i := 0; i < idx; i++ {
		data = append(data, ps.RawASEntries[i].Pack()...)
	}
	data = append(data, ps.RawASEntries[idx].Blob...)
	return data
}

func (ps *PathSegment) MaxAEIdx() int {
	return len(ps.RawASEntries) - 1
}

func (ps *PathSegment) validateIdx(idx int) error {
	if idx < 0 || idx > ps.MaxAEIdx() {
		return common.NewBasicError("Invalid ASEntry index", nil,
			"min", 0, "max", ps.MaxAEIdx(), "actual", idx)
	}
	return nil
}

// ShallowCopy creates a shallow copy of the path segment.
func (ps *PathSegment) ShallowCopy() *PathSegment {
	if ps == nil {
		return nil
	}
	rawEntries := make([]*proto.SignedBlobS, len(ps.RawASEntries))
	copy(rawEntries, ps.RawASEntries)
	entries := make([]*ASEntry, len(ps.ASEntries))
	copy(entries, ps.ASEntries)
	return &PathSegment{
		RawSData:     ps.RawSData,
		SData:        ps.SData,
		RawASEntries: rawEntries,
		ASEntries:    entries,
	}
}

func (ps *PathSegment) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(ps, b)
}

func (ps *PathSegment) Pack() (common.RawBytes, error) {
	return proto.PackRoot(ps)
}

func (ps *PathSegment) ProtoId() proto.ProtoIdType {
	return proto.PathSegment_TypeID
}

func (ps *PathSegment) String() string {
	if ps == nil {
		return "<nil>"
	}
	desc := []string{
		ps.GetLoggingID(),
		util.TimeToCompact(ps.Timestamp()),
		ps.getHopsDescription(),
	}
	return strings.Join(desc, " ")
}

func (ps *PathSegment) GetLoggingID() string {
	return fmt.Sprintf("%x", ps.ID()[:12])
}

func (ps *PathSegment) getHopsDescription() string {
	description := []string{}
	for _, ase := range ps.ASEntries {
		hop_desc := getHopDescription(ase.IA(), ase.HopEntries[0])
		description = append(description, hop_desc)
	}
	// TODO(shitz): Add extensions.
	return strings.Join(description, ">")
}

func getHopDescription(ia addr.IA, hopEntry *HopEntry) string {
	hop := hopEntry.HopField
	hop_desc := []string{}
	if hop.ConsIngress > 0 {
		hop_desc = append(hop_desc, fmt.Sprintf("%v ", hop.ConsIngress))
	}
	hop_desc = append(hop_desc, ia.String())
	if hop.ConsEgress > 0 {
		hop_desc = append(hop_desc, fmt.Sprintf(" %v", hop.ConsEgress))
	}
	return strings.Join(hop_desc, "")
}
