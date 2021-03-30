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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
)

// Raw is a raw representation of the SCION (data-plane) path type. It is designed to parse as
// little as possible and should be used if performance matters.
type Raw struct {
	Base
	Raw []byte
}

// DecodeFromBytes only decodes the PathMetaHeader. Otherwise the nothing is decoded and simply kept
// as raw bytes.
func (s *Raw) DecodeFromBytes(data []byte) error {
	if err := s.Base.DecodeFromBytes(data); err != nil {
		return err
	}
	pathLen := s.Len()
	if len(data) < pathLen {
		return serrors.New("RawPath raw too short", "expected", pathLen, "actual", len(data))
	}
	s.Raw = data[:pathLen]
	return nil
}

// SerializeTo writes the path to a slice. The slice must be big enough to hold the entire data,
// otherwise an error is returned.
func (s *Raw) SerializeTo(b []byte) error {
	if s.Raw == nil {
		return serrors.New("raw is nil")
	}
	if minLen := s.Len(); len(b) < minLen {
		return serrors.New("buffer too small", "expected", minLen, "actual", len(b))
	}
	// XXX(roosd): This modifies the underlying buffer. Consider writing to data
	// directly.
	if err := s.PathMeta.SerializeTo(s.Raw[:MetaLen]); err != nil {
		return err
	}
	copy(b, s.Raw)
	return nil
}

// Reverse reverses the path such that it can be used in the reverse direction.
func (s *Raw) Reverse() (path.Path, error) {
	// XXX(shitz): The current implementation is not the most performant, since it parses the entire
	// path first. If this becomes a performance bottleneck, the implementation should be changed to
	// work directly on the raw representation.

	decoded, err := s.ToDecoded()
	if err != nil {
		return nil, err
	}
	reversed, err := decoded.Reverse()
	if err != nil {
		return nil, err
	}
	if err := reversed.SerializeTo(s.Raw); err != nil {
		return nil, err
	}
	err = s.DecodeFromBytes(s.Raw)
	return s, err
}

// ToDecoded transforms a scion.Raw to a scion.Decoded.
func (s *Raw) ToDecoded() (*Decoded, error) {
	// Serialize PathMeta to ensure potential changes are reflected Raw.
	if err := s.PathMeta.SerializeTo(s.Raw[:MetaLen]); err != nil {
		return nil, err
	}
	decoded := &Decoded{}
	if err := decoded.DecodeFromBytes(s.Raw); err != nil {
		return nil, err
	}
	return decoded, nil
}

// IncPath increments the path and writes it to the buffer.
func (s *Raw) IncPath() error {
	if err := s.Base.IncPath(); err != nil {
		return err
	}
	return s.PathMeta.SerializeTo(s.Raw[:MetaLen])
}

// GetInfoField returns the InfoField at a given index.
func (s *Raw) GetInfoField(idx int) (*path.InfoField, error) {
	if idx >= s.NumINF {
		return nil, serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	infOffset := MetaLen + idx*path.InfoLen
	info := &path.InfoField{}
	if err := info.DecodeFromBytes(s.Raw[infOffset : infOffset+path.InfoLen]); err != nil {
		return nil, err
	}
	return info, nil
}

// GetCurrentInfoField is a convenience method that returns the current hop field pointed to by the
// CurrINF index in the path meta header.
func (s *Raw) GetCurrentInfoField() (*path.InfoField, error) {
	return s.GetInfoField(int(s.PathMeta.CurrINF))
}

// SetInfoField updates the InfoField at a given index.
func (s *Raw) SetInfoField(info *path.InfoField, idx int) error {
	if idx >= s.NumINF {
		return serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	if info == nil {
		return serrors.New("Infofield cannot be nil")
	}
	infOffset := MetaLen + idx*path.InfoLen
	return info.SerializeTo(s.Raw[infOffset : infOffset+path.InfoLen])
}

// GetHopField returns the HopField at a given index.
func (s *Raw) GetHopField(idx int) (*path.HopField, error) {
	if idx >= s.NumHops {
		return nil, serrors.New("HopField index out of bounds", "max", s.NumHops-1, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*path.HopLen
	hop := &path.HopField{}
	if err := hop.DecodeFromBytes(s.Raw[hopOffset : hopOffset+path.HopLen]); err != nil {
		return nil, err
	}
	return hop, nil
}

// GetCurrentHopField is a convenience method that returns the current hop field pointed to by the
// CurrHF index in the path meta header.
func (s *Raw) GetCurrentHopField() (*path.HopField, error) {
	return s.GetHopField(int(s.PathMeta.CurrHF))
}

// SetHopField updates the HopField at a given index.
func (s *Raw) SetHopField(hop *path.HopField, idx int) error {
	if idx >= s.NumHops {
		return serrors.New("HopField index out of bounds", "max", s.NumHops-1, "actual", idx)
	}
	if hop == nil {
		return serrors.New("Hopfield cannot be nil")
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*path.HopLen
	return hop.SerializeTo(s.Raw[hopOffset : hopOffset+path.HopLen])
}

// IsPenultimateHop returns whether the current hop is the penultimate hop on the path.
func (s *Raw) IsPenultimateHop() bool {
	numberHops := s.NumHops
	currentHop := int(s.PathMeta.CurrHF)
	return currentHop == numberHops-2
}

// IsLastHop returns whether the current hop is the last hop on the path.
func (s *Raw) IsLastHop() bool {
	numberHops := s.NumHops
	currentHop := int(s.PathMeta.CurrHF)
	return currentHop == numberHops-1
}
