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
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

const (
	// MaxINFs is the maximum number of info fields in a SCION path.
	MaxINFs = 3
	// MaxHops is the maximum number of hop fields in a SCION path.
	MaxHops = 64
)

// Decoded implements the SCION (data-plane) path type. Decoded is intended to be used in
// non-performance critical code paths, where the convenience of having a fully parsed path trumps
// the loss of performance.
type Decoded struct {
	Base
	// InfoFields contains all the InfoFields of the path.
	InfoFields []path.InfoField
	// HopFields contains all the HopFields of the path.
	HopFields []path.HopField
}

// DecodeFromBytes fully decodes the SCION path into the corresponding fields.
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
	s.HopFields = make([]path.HopField, s.NumHops)
	for i := 0; i < s.NumHops; i++ {
		if err := s.HopFields[i].DecodeFromBytes(data[offset : offset+path.HopLen]); err != nil {
			return err
		}
		offset += path.HopLen
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
	if err := s.PathMeta.SerializeTo(b[:MetaLen]); err != nil {
		return err
	}
	offset := MetaLen
	for _, info := range s.InfoFields {
		if err := info.SerializeTo(b[offset : offset+path.InfoLen]); err != nil {
			return err
		}
		offset += path.InfoLen
	}
	for _, hop := range s.HopFields {
		if err := hop.SerializeTo(b[offset : offset+path.HopLen]); err != nil {
			return err
		}
		offset += path.HopLen
	}
	return nil
}

// Reverse reverses a SCION path.
func (s *Decoded) Reverse() (path.Path, error) {
	if s.NumINF == 0 {
		return nil, serrors.New("empty decoded path is invalid and cannot be reversed")
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
	for i, j := 0, s.NumHops-1; i < j; i, j = i+1, j-1 {
		s.HopFields[i], s.HopFields[j] = s.HopFields[j], s.HopFields[i]
	}
	// Update CurrINF and CurrHF and SegLens
	s.PathMeta.CurrINF = uint8(s.NumINF) - s.PathMeta.CurrINF - 1
	s.PathMeta.CurrHF = uint8(s.NumHops) - s.PathMeta.CurrHF - 1

	return s, nil
}

// ToRaw tranforms scion.Decoded into scion.Raw.
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
