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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*PathSegment)(nil)

type PathSegment struct {
	RawSData     common.RawBytes        `capnp:"sdata"`
	SData        *PathSegmentSignedData `capnp:"-"`
	RawASEntries []*proto.SignedBlobS   `capnp:"asEntries"`
	// ASEntries contains the AS entries.
	// WARNING: Should never be modified! Use AddASEntry or create a new Segment instead.
	ASEntries []*ASEntry `capnp:"-"`
	id        common.RawBytes
	fullId    common.RawBytes
}

func NewSeg(infoF *spath.InfoField) (*PathSegment, error) {
	pss := newPathSegmentSignedData(infoF)
	rawPss, err := proto.PackRoot(pss)
	if err != nil {
		return nil, err
	}
	ps := &PathSegment{RawSData: rawPss, SData: pss}
	return ps, nil
}

func NewSegFromRaw(b common.RawBytes) (*PathSegment, error) {
	ps := &PathSegment{}
	err := proto.ParseFromRaw(ps, ps.ProtoId(), b)
	if err != nil {
		return nil, err
	}
	return ps, ps.ParseRaw()
}

func (ps *PathSegment) ParseRaw() error {
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
	return ps.Validate()
}

// ID returns a hash of the segment covering all hops, except for peerings.
func (ps *PathSegment) ID() (common.RawBytes, error) {
	if ps.id == nil {
		id, err := ps.calculateHash(true)
		if err != nil {
			return nil, err
		}
		ps.id = id
	}
	return ps.id, nil
}

// FullId returns a hash of the segment covering all hops including peerings.
func (ps *PathSegment) FullId() (common.RawBytes, error) {
	if ps.fullId == nil {
		fullId, err := ps.calculateHash(false)
		if err != nil {
			return nil, err
		}
		ps.fullId = fullId
	}
	return ps.fullId, nil
}

func (ps *PathSegment) calculateHash(hopOnly bool) (common.RawBytes, error) {
	h := sha256.New()
	for _, ase := range ps.ASEntries {
		binary.Write(h, common.Order, ase.RawIA)
		for _, hopE := range ase.HopEntries {
			hopf, err := hopE.HopField()
			if err != nil {
				return nil, err
			}
			binary.Write(h, common.Order, hopf.ConsIngress)
			binary.Write(h, common.Order, hopf.ConsEgress)
			if hopOnly {
				break
			}
		}
	}
	return h.Sum(nil), nil
}

func (ps *PathSegment) InfoF() (*spath.InfoField, error) {
	return ps.SData.InfoF()
}

func (ps *PathSegment) Validate() error {
	if err := ps.SData.Validate(); err != nil {
		return err
	}
	if len(ps.RawASEntries) == 0 {
		return common.NewBasicError("PathSegment has no AS Entries", nil)
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
		if err := ps.ASEntries[i].Validate(prevIA, nextIA); err != nil {
			return err
		}
	}
	// Check that all hop fields can be extracted
	if err := ps.WalkHopEntries(); err != nil {
		return err
	}
	return nil
}

func (ps *PathSegment) ContainsInterface(ia addr.IA, ifid common.IFIDType) bool {
	for _, asEntry := range ps.ASEntries {
		for _, entry := range asEntry.HopEntries {
			hf, err := entry.HopField()
			if err != nil {
				// This should not happen, as Validate already checks that it
				// is possible to extract the hop field.
				panic(err)
			}
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

	info, err := ps.InfoF()
	if err != nil {
		// This should not happen, as Validate already checks that infoF can be parsed.
		panic(err)
	}
	ttl := initTtl
	for _, asEntry := range ps.ASEntries {
		for _, he := range asEntry.HopEntries {
			hf, err := he.HopField()
			if err != nil {
				// This should not happen, as Validate already checks that it
				// is possible to extract the hop field.
				panic(err)
			}
			hfTtl := hf.ExpTime.ToDuration()
			if compare(hfTtl, ttl) {
				ttl = hfTtl
			}
		}
	}
	return info.Timestamp().Add(ttl)
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
func (ps *PathSegment) WalkHopEntries() error {
	for _, asEntry := range ps.ASEntries {
		for _, hopEntry := range asEntry.HopEntries {
			_, err := hopEntry.HopField()
			if err != nil {
				return common.NewBasicError("invalid hop field found in ASEntry",
					err, "asEntry", asEntry)
			}
		}
	}
	return nil
}

func (ps *PathSegment) AddASEntry(ase *ASEntry, signType proto.SignType,
	signSrc common.RawBytes) error {
	rawASE, err := ase.Pack()
	if err != nil {
		return err
	}
	ps.RawASEntries = append(ps.RawASEntries, &proto.SignedBlobS{
		Blob: rawASE,
		Sign: proto.NewSignS(signType, signSrc),
	})
	ps.ASEntries = append(ps.ASEntries, ase)
	ps.invalidateIds()
	return nil
}

func (ps *PathSegment) invalidateIds() {
	ps.id = nil
	ps.fullId = nil
}

func (ps *PathSegment) SignLastASEntry(key common.RawBytes) error {
	idx := ps.MaxAEIdx()
	packed, err := ps.sigPack(idx)
	if err != nil {
		return err
	}
	return ps.RawASEntries[idx].Sign.SignAndSet(key, packed)
}

func (ps *PathSegment) VerifyASEntry(key common.RawBytes, idx int) error {
	packed, err := ps.sigPack(idx)
	if err != nil {
		return err
	}
	return ps.RawASEntries[idx].Sign.Verify(key, packed)
}

func (ps *PathSegment) sigPack(idx int) (common.RawBytes, error) {
	if err := ps.validateIdx(idx); err != nil {
		return nil, err
	}
	data := append(common.RawBytes(nil), ps.RawSData...)
	for i := 0; i < idx; i++ {
		data = append(data, ps.RawASEntries[i].Pack()...)
	}
	data = append(data, ps.RawASEntries[idx].Blob...)
	return data, nil
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

func (ps *PathSegment) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(ps, b)
}

// RawWriteTo writes the PathSegment to the writer in a form that is understood by spath/Path.
func (ps *PathSegment) RawWriteTo(w io.Writer) (int64, error) {
	var total int64
	inf, err := ps.InfoF()
	if err != nil {
		return total, err
	}
	inf.Hops = uint8(len(ps.ASEntries))
	n, err := inf.WriteTo(w)
	total += n
	if err != nil {
		return total, err
	}
	for _, asEntry := range ps.ASEntries {
		if len(asEntry.HopEntries) == 0 {
			return total, common.NewBasicError("ASEntry has no HopEntry", nil, "asEntry", asEntry)
		}
		hf, err := asEntry.HopEntries[0].HopField()
		if err != nil {
			return total, err
		}
		n, err = hf.WriteTo(w)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
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
	info, _ := ps.InfoF()
	desc := []string{
		ps.GetLoggingID(),
		util.TimeToString(info.Timestamp()),
		ps.getHopsDescription(),
	}
	return strings.Join(desc, " ")
}

func (ps *PathSegment) GetLoggingID() string {
	id, err := ps.ID()
	if err != nil {
		return fmt.Sprintf("ID error: %s", err)
	}
	return id.String()[:12]
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
	hop, err := hopEntry.HopField()
	if err != nil {
		return err.Error()
	}
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
