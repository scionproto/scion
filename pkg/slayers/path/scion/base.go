// Copyright 2020 Anapaya Systems
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

package scion

import (
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// MetaLen is the length of the PathMetaHeader.
const MetaLen = 4

const PathType path.Type = 1

func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "SCION",
		New: func() path.Path {
			return &Raw{}
		},
	})
}

// Base holds the basic information that is used by both raw and fully decoded paths.
type Base struct {
	// PathMeta is the SCION path meta header. It is always instantiated when
	// decoding a path from bytes.
	PathMeta MetaHdr
	// NumINF is the number of InfoFields in the path.
	NumINF int
	// NumHops is the number HopFields in the path.
	NumHops int
}

func (s *Base) DecodeFromBytes(data []byte) error {
	// PathMeta takes care of bounds check.
	err := s.PathMeta.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	s.NumINF = 0
	s.NumHops = 0
	for i := 2; i >= 0; i-- {
		if s.PathMeta.SegLen[i] == 0 && s.NumINF > 0 {
			return serrors.New(
				fmt.Sprintf("Meta.SegLen[%d] == 0, but Meta.SegLen[%d] > 0", i, s.NumINF-1))
		}
		if s.PathMeta.SegLen[i] > 0 && s.NumINF == 0 {
			s.NumINF = i + 1
		}
		s.NumHops += int(s.PathMeta.SegLen[i])
	}
	return nil
}

// IncPath increases the currHF index and currINF index if appropriate.
func (s *Base) IncPath() error {
	if s.NumINF == 0 {
		return serrors.New("empty path cannot be increased")
	}
	if int(s.PathMeta.CurrHF) >= s.NumHops-1 {
		s.PathMeta.CurrHF = uint8(s.NumHops - 1)
		return serrors.New("path already at end",
			"curr_hf", s.PathMeta.CurrHF,
			"num_hops", s.NumHops)
	}
	s.PathMeta.CurrHF++
	// Update CurrINF
	s.PathMeta.CurrINF = s.infIndexForHF(s.PathMeta.CurrHF)
	return nil
}

// IsXover returns whether we are at a crossover point. This includes
// all segment switches, even over a peering link. Note that handling
// of a regular segment switch and handling of a segment switch over a
// peering link are fundamentally different. To distinguish the two,
// you will need to extract the information from the info field.
func (s *Base) IsXover() bool {
	return s.PathMeta.CurrHF+1 < uint8(s.NumHops) &&
		s.PathMeta.CurrINF != s.infIndexForHF(s.PathMeta.CurrHF+1)
}

// IsFirstHopAfterXover returns whether this is the first hop field after a crossover point.
func (s *Base) IsFirstHopAfterXover() bool {
	return s.PathMeta.CurrINF > 0 && s.PathMeta.CurrHF > 0 &&
		s.PathMeta.CurrINF-1 == s.infIndexForHF(s.PathMeta.CurrHF-1)
}

func (s *Base) infIndexForHF(hf uint8) uint8 {
	switch {
	case hf < s.PathMeta.SegLen[0]:
		return 0
	case hf < s.PathMeta.SegLen[0]+s.PathMeta.SegLen[1]:
		return 1
	default:
		return 2
	}
}

// Len returns the length of the path in bytes.
func (s *Base) Len() int {
	return MetaLen + s.NumINF*path.InfoLen + s.NumHops*path.HopLen
}

// Type returns the type of the path.
func (s *Base) Type() path.Type {
	return PathType
}

// MetaHdr is the PathMetaHdr of a SCION (data-plane) path type.
type MetaHdr struct {
	CurrINF uint8
	CurrHF  uint8
	SegLen  [3]uint8
}

// DecodeFromBytes populates the fields from a raw buffer. The buffer must be of length >=
// scion.MetaLen.
func (m *MetaHdr) DecodeFromBytes(raw []byte) error {
	if len(raw) < MetaLen {
		return serrors.New("MetaHdr raw too short", "expected", MetaLen, "actual", len(raw))
	}
	line := binary.BigEndian.Uint32(raw)
	m.CurrINF = uint8(line >> 30)
	m.CurrHF = uint8(line>>24) & 0x3F
	m.SegLen[0] = uint8(line>>12) & 0x3F
	m.SegLen[1] = uint8(line>>6) & 0x3F
	m.SegLen[2] = uint8(line) & 0x3F

	return nil
}

// SerializeTo writes the fields into the provided buffer. The buffer must be of length >=
// scion.MetaLen.
func (m *MetaHdr) SerializeTo(b []byte) error {
	if len(b) < MetaLen {
		return serrors.New("buffer for MetaHdr too short", "expected", MetaLen, "actual", len(b))
	}
	line := uint32(m.CurrINF)<<30 | uint32(m.CurrHF&0x3F)<<24
	line |= uint32(m.SegLen[0]&0x3F) << 12
	line |= uint32(m.SegLen[1]&0x3F) << 6
	line |= uint32(m.SegLen[2] & 0x3F)
	binary.BigEndian.PutUint32(b, line)

	return nil
}

func (m MetaHdr) String() string {
	return fmt.Sprintf("{CurrInf: %d, CurrHF: %d, SegLen: %v}", m.CurrINF, m.CurrHF, m.SegLen)
}
