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
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

const MetaLen = 12

func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "Hummingbird",
		New: func() path.Path {
			return &Raw{}
		},
	})
}

// Base holds the basic information that is used by both raw and fully decoded paths.
type Base struct {
	// PathMeta is the Hummingbird path meta header. It is always instantiated when
	// decoding a path from bytes.
	PathMeta MetaHdr
	// NumINF is the number of InfoFields in the path.
	NumINF int
	// NumLines is the number of 4 bytes lines in the path. NumLines = SegLen[i] for 0<=i<=2.
	NumLines int
}

// DecodeFromBytes populates the fields from a raw buffer. The buffer must be of length >=
// hummingbird.MetaLen.
func (s *Base) DecodeFromBytes(data []byte) error {
	// PathMeta checks bounds.
	err := s.PathMeta.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	s.NumINF = 0
	s.NumLines = 0
	for i := 2; i >= 0; i-- {
		if s.PathMeta.SegLen[i] == 0 && s.NumINF > 0 {
			return serrors.New(
				fmt.Sprintf("Meta.SegLen[%d] == 0, but Meta.SegLen[%d] > 0", i, s.NumINF-1))
		}
		if s.PathMeta.SegLen[i] > 0 && s.NumINF == 0 {
			s.NumINF = i + 1
		}
		s.NumLines += int(s.PathMeta.SegLen[i])
	}
	return nil
}

// IncPath increases the currHF index by n and the currINF index if appropriate.
func (s *Base) IncPath(n int) error {
	if s.NumINF == 0 {
		return serrors.New("empty path cannot be increased")
	}
	if int(s.PathMeta.CurrHF) >= s.NumLines-n {
		return serrors.New("Incrementing path over end")
	}
	s.PathMeta.CurrHF += uint8(n)
	s.PathMeta.CurrINF = s.InfIndexForHF(s.PathMeta.CurrHF)
	return nil
}

// IsXover returns whether we are at a crossover point.
func (s *Base) IsXover() bool {
	return s.PathMeta.CurrHF+FlyoverLines < uint8(s.NumLines) &&
		(s.PathMeta.CurrINF != s.InfIndexForHF(s.PathMeta.CurrHF+HopLines) ||
			s.PathMeta.CurrINF != s.InfIndexForHF(s.PathMeta.CurrHF+FlyoverLines))

}

// IsFirstHopAfterXover returns whether this is the first hop field after a crossover point.
func (s *Base) IsFirstHopAfterXover() bool {
	return s.PathMeta.CurrINF > 0 && s.PathMeta.CurrHF > 0 &&
		s.PathMeta.CurrINF-1 == s.InfIndexForHF(s.PathMeta.CurrHF-1)
}

// InfIndexForHF returns the segment to which the HopField hf belongs
// The argument hfLines is the line count until the first line of this hop field.
func (s *Base) InfIndexForHF(hfLines uint8) uint8 {
	switch {
	case hfLines < s.PathMeta.SegLen[0]:
		return 0
	case hfLines < s.PathMeta.SegLen[0]+s.PathMeta.SegLen[1]:
		return 1
	default:
		return 2
	}
}

// Len returns the length of the path in bytes.
func (s *Base) Len() int {
	return MetaLen + s.NumINF*path.InfoLen + s.NumLines*LineLen
}

// Type returns the type of the path.
func (s *Base) Type() path.Type {
	return PathType
}

// MetaHdr is the PathMetaHdr of a Hummingbird (data-plane) path type.
type MetaHdr struct {
	CurrINF   uint8    // Index of the current info field.
	CurrHF    uint8    // Index of the current hop field.
	SegLen    [3]uint8 // Length in bytes / 4 of each segment.
	BaseTS    uint32
	HighResTS uint32
}

// DecodeFromBytes populates the fields from a raw buffer. The buffer must be of length >=
// hummingbird.MetaLen.
func (m *MetaHdr) DecodeFromBytes(raw []byte) error {
	if len(raw) < MetaLen {
		return serrors.New("MetaHdr raw too short", "expected", MetaLen, "actual", len(raw))
	}
	line := binary.BigEndian.Uint32(raw[0:4])
	m.CurrINF = uint8(line >> 30)
	m.CurrHF = uint8(line >> 22)
	m.SegLen[0] = uint8(line>>14) & 0x7F
	m.SegLen[1] = uint8(line>>7) & 0x7F
	m.SegLen[2] = uint8(line) & 0x7F

	m.BaseTS = binary.BigEndian.Uint32(raw[4:8])
	m.HighResTS = binary.BigEndian.Uint32(raw[8:12])

	return nil
}

// SerializeTo writes the fields into the provided buffer. The buffer must be of length >=
// hummingbird.MetaLen.
func (m *MetaHdr) SerializeTo(b []byte) error {
	if len(b) < MetaLen {
		return serrors.New("buffer for MetaHdr too short", "expected", MetaLen, "actual", len(b))
	}
	line := uint32(m.CurrINF)<<30 | uint32(m.CurrHF)<<22
	line |= uint32(m.SegLen[0]&0x7F) << 14
	line |= uint32(m.SegLen[1]&0x7F) << 7
	line |= uint32(m.SegLen[2] & 0x7F)
	binary.BigEndian.PutUint32(b[0:4], line)

	binary.BigEndian.PutUint32(b[4:8], m.BaseTS)
	binary.BigEndian.PutUint32(b[8:12], m.HighResTS)

	return nil
}

func (m MetaHdr) String() string {
	return fmt.Sprintf(
		"{CurrInf: %d, CurrHF: %d, SegLen: %v, BaseTimestamp: %v, HighResTimestamp: %v}",
		m.CurrINF, m.CurrHF, m.SegLen, m.BaseTS, m.HighResTS)
}
