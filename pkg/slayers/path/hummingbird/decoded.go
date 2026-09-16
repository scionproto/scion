// Copyright 2025 ETH Zurich
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

package hummingbird

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

const (
	// MaxINFs is the maximum number of info fields in a Hummingbird path.
	MaxINFs = 3
	// MaxHops is the maximum number of hop fields in a Hummingbird path.
	MaxHops = 85
)

// Decoded implements the Hummingbird (data-plane) path type. Decoded is intended to be used in
// non-performance critical code paths, where the convenience of having a fully parsed path trumps
// the loss of performance.
type Decoded struct {
	Base
	// InfoFields contains all the InfoFields of the path.
	InfoFields []path.InfoField
	// HopFields contains all the HopFields of the path.
	HopFields []FlyoverHopField
	// FirstHopPerSeg notes the index of the first hopfield of the second and third segment
	FirstHopPerSeg [2]uint8
}

func (s *Decoded) decodeAllHFs(data []byte) error {
	origData := data
	l := s.NumLines * LineLen
	if len(data) < l {
		return serrors.New("buffer too small", "expected", l, "actual", len(data))
	}
	data = data[:l]

	// Allocate maximum number of possible hopfields based on length
	s.HopFields = make([]FlyoverHopField, s.NumLines/HopLines)

	hfIdx := 0
	for segIdx, segRemFromHeader := range s.PathMeta.SegLen {
		// segIdx is the segment index [0,1,2]
		// segRem is the lines-to-be-read remainder.
		segRem := int(segRemFromHeader)
		for ; segRem > 0; hfIdx++ {
			if len(data) < hopLen {
				return serrors.New("malformed hummingbird path or buffer too small",
					"hf_idx", hfIdx, "buff_size", len(origData))
			}
			isFlyover := data[0]&0x80 == 0x80
			bLen := hopLen
			if isFlyover {
				bLen = flyoverLen
			}
			// Check we are not out of bounds.
			if bLen > len(data) {
				return serrors.New("flyover hopfield truncated in buffer",
					"hf_idx", hfIdx, "buff_size", len(origData))
			}
			segRem -= (bLen / LineLen)

			// Parse the hop field.
			if err := s.HopFields[hfIdx].DecodeFromBytes(data[:bLen]); err != nil {
				return serrors.Join(err, nil, "hf_idx", hfIdx)
			}

			// Advance the buffer by the size of the last hop field.
			data = data[bLen:]
		}
		if segRem != 0 {
			return serrors.New("malformed hummingbird path",
				"hf_idx", hfIdx, "seg_idx", segIdx, "seg_remainder", segRem)
		}
		if segIdx < 2 {
			// If we finished the segment 0 or 1, record where the next one starts.
			s.FirstHopPerSeg[segIdx] = uint8(hfIdx)
		}
	}

	if hfIdx > MaxHops {
		return serrors.New("too many hop fields", "max", MaxHops, "actual", hfIdx)
	}

	// Cull the HF slice to the last HF.
	s.HopFields = s.HopFields[:hfIdx]

	return nil
}

// DecodeFromBytes fully decodes the Hummingbird path into the corresponding fields.
func (s *Decoded) DecodeFromBytes(data []byte) error {
	if err := s.Base.DecodeFromBytes(data); err != nil {
		return err
	}
	if minLen := s.Len(); len(data) < minLen {
		return serrors.New("DecodedPath raw too short", "expected", minLen, "actual", len(data))
	}

	offset := MetaLen
	s.InfoFields = make([]path.InfoField, s.NumINF)
	for i := 0; i < s.NumINF; i++ {
		if err := s.InfoFields[i].DecodeFromBytes(data[offset : offset+path.InfoLen]); err != nil {
			return err
		}
		offset += path.InfoLen
	}
	if err := s.decodeAllHFs(data[offset:]); err != nil {
		return err
	}

	return nil
}

// SerializeTo writes the path to a slice. The slice must be big enough to hold the entire data,
// otherwise an error is returned.
func (s *Decoded) SerializeTo(b []byte) error {
	if len(b) < s.Len() {
		return serrors.New("buffer too small to serialize path.", "expected", s.Len(),
			"actual", len(b))
	}
	var offset int

	offset = MetaLen
	if err := s.PathMeta.SerializeTo(b[:MetaLen]); err != nil {
		return err
	}

	for _, info := range s.InfoFields {
		if err := info.SerializeTo(b[offset : offset+path.InfoLen]); err != nil {
			return err
		}
		offset += path.InfoLen
	}
	for _, hop := range s.HopFields {
		if hop.Flyover {
			if err := hop.SerializeTo(b[offset : offset+flyoverLen]); err != nil {
				return err
			}
			offset += flyoverLen
		} else {
			if err := hop.SerializeTo(b[offset : offset+hopLen]); err != nil {
				return err
			}
			offset += hopLen
		}
	}
	return nil
}

// Reverse reverses a hummingbird path.
// Removes all reservations from a Hummingbird path, as these are not bidirectional
func (s *Decoded) Reverse() (path.Path, error) {
	if s.NumINF == 0 {
		return nil, serrors.New("empty decoded path is invalid and cannot be reversed")
	}

	if err := s.RemoveFlyovers(); err != nil {
		return nil, err
	}
	// Reverse order of InfoFields and SegLens
	for i, j := 0, s.NumINF-1; i < j; i, j = i+1, j-1 {
		s.InfoFields[i], s.InfoFields[j] = s.InfoFields[j], s.InfoFields[i]
		s.PathMeta.SegLen[i], s.PathMeta.SegLen[j] = s.PathMeta.SegLen[j], s.PathMeta.SegLen[i]
	}
	// Reverse cons dir flags
	for i := 0; i < s.NumINF; i++ {
		info := &s.InfoFields[i]
		info.ConsDir = !info.ConsDir
	}
	// Reverse order of hop fields
	for i, j := 0, len(s.HopFields)-1; i < j; i, j = i+1, j-1 {
		s.HopFields[i], s.HopFields[j] = s.HopFields[j], s.HopFields[i]
	}
	// Update CurrINF and CurrHF and SegLens
	s.PathMeta.CurrINF = uint8(s.NumINF) - s.PathMeta.CurrINF - 1
	s.PathMeta.CurrHF = uint8(s.NumLines) - s.PathMeta.CurrHF - HopLines
	s.FirstHopPerSeg[0] = uint8(len(s.HopFields))
	s.FirstHopPerSeg[1] = uint8(len(s.HopFields))
	if s.PathMeta.SegLen[1] != 0 {
		s.FirstHopPerSeg[0] = s.PathMeta.SegLen[0] / HopLines
	}
	if s.PathMeta.SegLen[2] != 0 {
		s.FirstHopPerSeg[1] = s.FirstHopPerSeg[0] + s.PathMeta.SegLen[1]/HopLines
	}

	return s, nil
}

// RemoveFlyovers removes all reservations from a decoded path
// Corrects SegLen and CurrHF accordingly
// Does not affect MACs
func (s *Decoded) RemoveFlyovers() error {
	var idxInf uint8 = 0
	var offset uint8 = 0
	var segCount uint8 = 0

	for i, hop := range s.HopFields {
		if idxInf > 2 {
			return serrors.New("path appears to have more than 3 segments during flyover removal")
		}
		if hop.Flyover {
			s.HopFields[i].Flyover = false

			if s.PathMeta.CurrHF > offset {
				s.PathMeta.CurrHF -= 2
			}
			s.Base.NumLines -= 2
			s.PathMeta.SegLen[idxInf] -= 2
		}
		segCount += HopLines
		if s.PathMeta.SegLen[idxInf] == segCount {
			segCount = 0
			idxInf += 1
		} else if s.PathMeta.SegLen[idxInf] < segCount {
			return serrors.New(
				"New hopfields boundaries do not match new segment lengths after flyover removal")
		}
		offset += HopLines
	}
	return nil
}

// ToRaw tranforms hummingbird.Decoded into hummingbird.Raw.
func (s *Decoded) ToRaw() (*Raw, error) {
	b := make([]byte, s.Len())
	if err := s.SerializeTo(b); err != nil {
		return nil, err
	}
	raw := &Raw{}
	if err := raw.DecodeFromBytes(b); err != nil {
		return nil, err
	}
	return raw, nil
}

// GetHopField returns the hop field starting at the specified line offset.
func (s *Decoded) GetHopField(hfLine uint8) (FlyoverHopField, error) {
	// A path can span more lines than a uint8, use int.
	lineCount := 0
	for _, hop := range s.HopFields {
		if lineCount == int(hfLine) {
			return hop, nil
		}
		if lineCount > int(hfLine) {
			// hfLine falls inside the previous hop field rather than at the start of one.
			break
		}
		if hop.Flyover {
			lineCount += FlyoverLines
		} else {
			lineCount += HopLines
		}
	}
	return FlyoverHopField{}, serrors.New(
		"no hop field starts at this line", "max", lineCount, "actual", hfLine)
}

// GetCurrentHopField returns the current hop field pointed to by CurrHF.
func (s *Decoded) GetCurrentHopField() (FlyoverHopField, error) {
	return s.GetHopField(s.PathMeta.CurrHF)
}

// InfIndexForHFIndex takes the index of the hop field in the HopFields slice and returns its
// corresponding info field index in the InfoFields slice. Expected 0 <= hfIdx < len(HopFields).
func (s *Decoded) InfIndexForHFIndex(hfIdx uint8) uint8 {
	// A path can span more lines than a uint8, use int.
	lineCount := 0
	for i := range hfIdx {
		if s.HopFields[i].Flyover {
			lineCount += FlyoverLines
		} else {
			lineCount += HopLines
		}
	}
	return s.infIndexForLine(lineCount)
}

func (s Decoded) NumberOfHFsInSegment(segmentIndex int) int {
	// Guard against out of valid segment indices. Negative indices are passed to the default case.
	if segmentIndex >= s.NumINF {
		return 0
	}

	switch segmentIndex {
	case 0:
		return int(s.FirstHopPerSeg[0])
	case 1:
		return int(s.FirstHopPerSeg[1] - s.FirstHopPerSeg[0])
	case 2:
		return len(s.HopFields) - int(s.FirstHopPerSeg[1])
	default:
		return 0
	}
}

// IsCrossOver returns -1 for the first hop of a crossover, +1 for the second, or 0 for none.
// This function returns no-crossover for peering links, as opposed to the scion.Base.IsXover,
// which is true even in the presence of peering links.
func (s Decoded) IsCrossOver(hfIdx uint8) int {
	// A crossover is the "joining" of two segments.
	//
	// A peering link joins two segments as well, but it is not a crossover: the two hop fields on
	// either side of it belong to two different ASes and each describes a real traversal, whereas
	// the two hop fields of a crossover describe the same AS and collapse into one logical hop.

	idx := int(hfIdx)
	for i := range s.NumINF - 1 {
		c := s.NumberOfHFsInSegment(i)
		peering := s.isPeeringBoundary(i)
		if idx == c-1 && !peering {
			// Last hop of first segment of the crossover.
			return -1
		}
		idx -= c
		if idx == 0 && !peering && int(hfIdx) != len(s.HopFields)-1 {
			// First hop of second segment of the crossover, and not destination AS.
			return 1
		}
	}

	return 0
}

// isPeeringBoundary returns whether the segments segIdx and segIdx+1 are joined by a peering link
// instead of by a crossover. Both info fields of a peering path carry the peer flag; a path where
// only one of them does is malformed, and is reported as peering so that no hop field is lost to
// a crossover collapse.
func (s Decoded) isPeeringBoundary(segIdx int) bool {
	if segIdx < 0 || segIdx+1 >= len(s.InfoFields) {
		return false
	}
	return s.InfoFields[segIdx].Peer || s.InfoFields[segIdx+1].Peer
}

// Converts a SCiON decoded path to a hummingbird decoded path
// Does NOT perform a deep copy of hop and info fields.
// Does NOT set the PathMeta Timestamps and counter
func (s *Decoded) ConvertFromScionDecoded(d *scion.Decoded) {
	// convert Base
	s.convertBaseFromScion(&d.Base)
	// transfer Infofields
	s.InfoFields = d.InfoFields
	// convert HopFields
	s.HopFields = make([]FlyoverHopField, d.NumHops)
	for i, hop := range d.HopFields {
		s.HopFields[i] = FlyoverHopField{
			HopField: hop,
			Flyover:  false,
		}
	}
	s.FirstHopPerSeg[0] = d.Base.PathMeta.SegLen[0]
	s.FirstHopPerSeg[1] = d.Base.PathMeta.SegLen[0] + d.Base.PathMeta.SegLen[1]
}

func (s *Decoded) convertBaseFromScion(d *scion.Base) {
	s.Base.NumINF = d.NumINF
	s.Base.PathMeta.CurrINF = d.PathMeta.CurrINF

	s.Base.NumLines = d.NumHops * HopLines
	s.Base.PathMeta.CurrHF = d.PathMeta.CurrHF * HopLines

	s.Base.PathMeta.SegLen[0] = d.PathMeta.SegLen[0] * HopLines
	s.Base.PathMeta.SegLen[1] = d.PathMeta.SegLen[1] * HopLines
	s.Base.PathMeta.SegLen[2] = d.PathMeta.SegLen[2] * HopLines
}
