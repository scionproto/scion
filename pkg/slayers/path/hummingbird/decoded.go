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

	// Allocate maximum number of possible hopfields based on length
	s.HopFields = make([]FlyoverHopField, s.NumLines/HopLines)
	i, j := 0, 0
	// If last hop is not a flyover hop, decode it with only 12 bytes slice
	for ; j < s.NumLines-HopLines; i++ {
		if err := s.HopFields[i].DecodeFromBytes(data[offset : offset+flyoverLen]); err != nil {
			return err
		}
		// Set FirstHopPerSeg
		if j == int(s.PathMeta.SegLen[0]) {
			s.FirstHopPerSeg[0] = uint8(i)
		} else if j == int(s.PathMeta.SegLen[0])+int(s.PathMeta.SegLen[1]) {
			s.FirstHopPerSeg[1] = uint8(i)
		}

		if s.HopFields[i].Flyover {
			offset += flyoverLen
			j += FlyoverLines
		} else {
			offset += hopLen
			j += HopLines
		}
	}
	if j == s.NumLines-HopLines {
		if err := s.HopFields[i].DecodeFromBytes(data[offset : offset+hopLen]); err != nil {
			return err
		}
		i++
	}
	s.HopFields = s.HopFields[:i]
	if s.PathMeta.SegLen[1] == 0 {
		s.FirstHopPerSeg[0] = uint8(i)
		s.FirstHopPerSeg[1] = uint8(i)
	} else if s.PathMeta.SegLen[2] == 0 {
		s.FirstHopPerSeg[1] = uint8(i)
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

	if err := s.removeFlyovers(); err != nil {
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

	return s, nil
}

// RemoveFlyovers removes all reservations from a decoded path
// Corrects SegLen and CurrHF accordingly
// Does not affect MACs
func (s *Decoded) removeFlyovers() error {
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

// InfIndexForHFIndex takes the index of the hop field in the HopFields slice and returns its
// corresponding info field index in the InfoFields slice. Expected 0 <= hfIdx < len(HopFields).
func (s *Decoded) InfIndexForHFIndex(hfIdx uint8) uint8 {
	lineCount := uint8(0)
	for i := uint8(0); i < hfIdx; i++ {
		if s.HopFields[i].Flyover {
			lineCount += FlyoverLines
		} else {
			lineCount += HopLines
		}
	}
	return s.InfIndexForHF(lineCount)
}

// Converts a SCiON decoded path to a hummingbird decoded path
// Does NOT perform a deep copy of hop and info fields.
// Does NOT set the PathMeta Timestamps and counter
func (s *Decoded) ConvertFromScionDecoded(d scion.Decoded) {
	// convert Base
	s.convertBaseFromScion(d.Base)
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

func (s *Decoded) convertBaseFromScion(d scion.Base) {
	s.Base.NumINF = d.NumINF
	s.Base.PathMeta.CurrINF = d.PathMeta.CurrINF

	s.Base.NumLines = d.NumHops * HopLines
	s.Base.PathMeta.CurrHF = d.PathMeta.CurrHF * HopLines

	s.Base.PathMeta.SegLen[0] = d.PathMeta.SegLen[0] * HopLines
	s.Base.PathMeta.SegLen[1] = d.PathMeta.SegLen[1] * HopLines
	s.Base.PathMeta.SegLen[2] = d.PathMeta.SegLen[2] * HopLines
}
