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

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// Raw is a raw representation of the Hummingbird (data-plane) path type. It is designed to parse as
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
// Removes all flyovers in the process
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

// ToDecoded transforms a hummingbird.Raw to a hummingbird.Decoded.
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

// IncPath increments the path by n and writes it to the buffer.
func (s *Raw) IncPath(n int) error {
	if err := s.Base.IncPath(n); err != nil {
		return err
	}

	return s.PathMeta.SerializeTo(s.Raw[:MetaLen])
}

// GetInfoField returns the InfoField at a given index.
func (s *Raw) GetInfoField(idx int) (path.InfoField, error) {
	if idx >= s.NumINF {
		return path.InfoField{},
			serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	infOffset := MetaLen + idx*path.InfoLen
	info := path.InfoField{}
	if err := info.DecodeFromBytes(s.Raw[infOffset : infOffset+path.InfoLen]); err != nil {
		return path.InfoField{}, err
	}
	return info, nil
}

// GetCurrentInfoField is a convenience method that returns the current info field pointed to by the
// CurrINF index in the path meta header.
func (s *Raw) GetCurrentInfoField() (path.InfoField, error) {
	return s.GetInfoField(int(s.PathMeta.CurrINF))
}

// Returns whether the hopfield at the given index is in construction direction
func (s *Raw) isConsdir(idx uint8) bool {
	hopIdx := s.Base.InfIndexForHF(idx)
	infOffset := MetaLen + hopIdx*path.InfoLen
	return s.Raw[infOffset]&0x1 == 0x1

}

// SetInfoField updates the InfoField at a given index.
func (s *Raw) SetInfoField(info path.InfoField, idx int) error {
	if idx >= s.NumINF {
		return serrors.New("InfoField index out of bounds", "max", s.NumINF-1, "actual", idx)
	}
	infOffset := MetaLen + idx*path.InfoLen
	return info.SerializeTo(s.Raw[infOffset : infOffset+path.InfoLen])
}

// GetHopField returns the HopField beginning at a given index.
// Does NOT check whether the given index is the first line of a hopfield
// Responsibility to check that falls to the caller
func (s *Raw) GetHopField(idx int) (FlyoverHopField, error) {
	if idx >= s.NumLines-HopLines+1 {
		return FlyoverHopField{},
			serrors.New("HopField index out of bounds", "max", s.NumLines-HopLines, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	hop := FlyoverHopField{}
	// Let the decoder read a big enough slice in case it is a FlyoverHopField
	maxHopLen := flyoverLen
	if idx > s.NumLines-FlyoverLines {
		if idx == s.NumLines-HopLines {
			maxHopLen = hopLen
		} else {
			return FlyoverHopField{}, serrors.New(
				"Invalid hopfield index", "NumHops", s.NumLines, "index", idx)
		}
	}
	if err := hop.DecodeFromBytes(s.Raw[hopOffset : hopOffset+maxHopLen]); err != nil {
		return FlyoverHopField{}, err
	}
	return hop, nil
}

// GetCurrentHopField is a convenience method that returns the current hop field pointed to by the
// CurrHF index in the path meta header.
func (s *Raw) GetCurrentHopField() (FlyoverHopField, error) {
	return s.GetHopField(int(s.PathMeta.CurrHF))
}

// ReplaceMac replaces the Mac of the hopfield at the given index with a new MAC.
func (s *Raw) ReplacMac(idx int, mac []byte) error {
	if idx >= s.NumLines-HopLines+1 {
		return serrors.New("HopField index out of bounds", "max",
			s.NumLines-HopLines, "actual", idx)
	}
	offset := s.NumINF*path.InfoLen + MetaLen + idx*LineLen + macOffset
	if n := copy(s.Raw[offset:offset+path.MacLen], mac[:path.MacLen]); n != path.MacLen {
		return serrors.New("copied worng number of bytes for mac replacement",
			"expected", path.MacLen, "actual", n)
	}
	return nil
}

// SetCurrentMac replaces the Mac of the current hopfield by a new MAC.
func (s *Raw) ReplaceCurrentMac(mac []byte) error {
	return s.ReplacMac(int(s.PathMeta.CurrHF), mac)
}

// Returns a slice of the MAC of the hopfield starting at index idx
// It is the caller's responsibility to make sure line idx is the beginning of a hopfield.
func (s *Raw) GetMac(idx int) ([]byte, error) {
	if idx >= s.NumLines-HopLines+1 {
		return nil, serrors.New("HopField index out of bounds",
			"max", s.NumLines-HopLines, "actual", idx)
	}
	offset := s.NumINF*path.InfoLen + MetaLen + idx*LineLen + macOffset
	return s.Raw[offset : offset+path.MacLen], nil
}

// SetHopField updates the HopField at a given index.
// For Hummingbird paths the index is the offset in 4 byte lines
//
// If replacing a FlyoverHopField with a Hopfield,
// it is replaced by a FlyoverHopField with dummy values.
// This works for SCMP packets as Flyover hops are removed later
// in the process of building a SCMP packet.
//
// Does not allow replacing a normal hopfield with a FlyoverHopField.
func (s *Raw) SetHopField(hop FlyoverHopField, idx int) error {
	if idx >= s.NumLines-HopLines+1 {
		return serrors.New("HopField index out of bounds",
			"max", s.NumLines-HopLines, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x80 {
		// If the current hop is a flyover, the flyover bit of the new hop is set to 1
		// in order to preserve correctness of the path.
		//
		// The reservation data of the new hop is dummy data and invalid.
		// This works because SetHopField is currently only used to prepare a SCMP packet,
		// and all flyovers are removed later in that process.
		//
		// If this is ever used for something else, this function needs to be re-written.
		hop.Flyover = true
	}
	if hop.Flyover {
		if idx >= s.NumLines-FlyoverLines+1 {
			return serrors.New("FlyoverHopField index out of bounds",
				"max", s.NumLines-FlyoverLines, "actual", idx)
		}
		hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
		if s.Raw[hopOffset]&0x80 == 0x00 {
			return serrors.New(
				"Setting FlyoverHopField over Hopfield with setHopField not supported")
		}
		return hop.SerializeTo(s.Raw[hopOffset : hopOffset+flyoverLen])
	}
	return hop.SerializeTo(s.Raw[hopOffset : hopOffset+hopLen])
}

// IsFirstHop returns whether the current hop is the first hop on the path.
func (s *Raw) IsFirstHop() bool {
	return s.PathMeta.CurrHF == 0
}

// IsLastHop returns whether the current hop is the last hop on the path.
func (s *Raw) IsLastHop() bool {
	return int(s.PathMeta.CurrHF) == (s.NumLines-HopLines) ||
		int(s.PathMeta.CurrHF) == (s.NumLines-FlyoverLines)
}

// Returns the egress interface of the next hop.
func (s *Raw) GetNextEgress() (uint16, error) {
	idx := int(s.Base.PathMeta.CurrHF)
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x80 {
		idx += FlyoverLines
		hopOffset += FlyoverLines * LineLen
	} else {
		idx += HopLines
		hopOffset += HopLines * LineLen
	}
	if idx >= s.NumLines-2 {
		return 0, serrors.New("HopField index out of bounds", "max",
			s.NumLines-HopLines, "actual", idx)
	}
	if s.isConsdir(uint8(idx)) {
		return binary.BigEndian.Uint16(s.Raw[hopOffset+4 : hopOffset+6]), nil
	}
	return binary.BigEndian.Uint16(s.Raw[hopOffset+2 : hopOffset+4]), nil
}

// Returns the ingress interface of the previous hop
// Does NOT work if the previous hop is a flyover hop.
func (s *Raw) GetPreviousIngress() (uint16, error) {
	idx := int(s.Base.PathMeta.CurrHF) - HopLines
	if idx < 0 {
		return 0, serrors.New("HopField index out of bounds", "min", 0, "actual", idx)
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.isConsdir(uint8(idx)) {
		return binary.BigEndian.Uint16(s.Raw[hopOffset+2 : hopOffset+4]), nil
	}
	return binary.BigEndian.Uint16(s.Raw[hopOffset+4 : hopOffset+6]), nil
}

// MoveFlyoverToNext attaches previous flyoverfield to current hopfield.
// DOES NOT adapt MACs.
// Assumes previous hopfield has a flyover.
// Assumes to be the first hop of the second or third segment.
// If a flyover is depicted like this:
//
//	Line index:			0 1 2 3 4 5
//						| hop |fly|
//
// Graphically, the byte buffer is transformed as follows:
//
//	-5 4 3 2 1 0 1 2 3                                 -5 4 3 2 1 0 1 2 3
//	 | flyovr1 | hop2|          gets morphed into:      | hop1| flyovr2 |
//
// Then the pointer to the current field is modified by substracting 2,
// as it starts now two lines before the original CurrHF.
// Because only the flyover part is copied, the fields ResID, BW, ResStartOffset, and Duration are
// correct, but not the MACs of the current or previous hop fields:
// - The previous hop field contains an aggregated MAC, but is no longer a flyover.
// - The current hop field contains only a MAC, but as a flyover it requires an aggregated MAC.
func (s *Raw) MoveFlyoverToNext() error {
	idx := int(s.Base.PathMeta.CurrHF)
	if idx >= s.NumLines-2 {
		return serrors.New("CurrHF out of bounds",
			"max", s.NumLines-2, "actual", idx)
	}
	prevHopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen - flyoverLen
	buff := s.Raw[prevHopOffset:] // buff points to the beginning of the previous hop
	if buff[flyoverLen]&0x80 == 0x80 {
		return serrors.New("Current hop does already have a Flyover")
	}
	// buffer flyover and copy data
	var temp [2 * LineLen]byte
	copy(
		temp[:],
		buff[hopLen:flyoverLen]) // save the flyover-only part (2 lines)
	copy(
		buff[hopLen:2*hopLen],
		buff[flyoverLen:flyoverLen+hopLen]) // copy the current hopfield in place (3 lines)
	copy(
		buff[2*hopLen:hopLen+flyoverLen],
		temp[:]) // copy back the flyover-only part, to the current hop

	// Unset and Set Flyoverbits
	buff[0] &= 0x7f      // Unset MSBit, flyover == false.
	buff[hopLen] |= 0x80 // Set MSbit, flyover == true.
	// Adapt seglens
	s.Base.PathMeta.CurrHF -= 2
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF-1] -= 2
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF] += 2
	return s.Base.PathMeta.SerializeTo(s.Raw[:])
}

// Attaches current flyoverfield to previous hopfield
// DOES NOT adapt MACs.
// It is assumed that the previous hopfield does NOT already have a flyover.
func (s *Raw) MoveFlyoverToPrevious() error {
	idx := int(s.Base.PathMeta.CurrHF)
	if idx < 6 {
		return serrors.New("CurrHF too small for reversing flyover crossover",
			"min", 6, "actual", idx)
	}
	if s.PathMeta.CurrINF == 0 {
		return serrors.New("Cannot reverse Flyover Xover when CurrINF = 0")
	}
	hopOffset := MetaLen + s.NumINF*path.InfoLen + idx*LineLen
	if s.Raw[hopOffset]&0x80 == 0x00 {
		return serrors.New("Current hop does not have a Flyover")
	}
	if s.Raw[hopOffset-hopLen]&0x80 != 0x00 {
		return serrors.New(
			"Cannot Reverse Flyover Crossover, flyover bit set where previous hop should be")
	}
	var t [flyoverLen - hopLen]byte
	copy(t[:], s.Raw[hopOffset+hopLen:hopOffset+flyoverLen])
	copy(s.Raw[hopOffset+flyoverLen-hopLen:hopOffset+flyoverLen],
		s.Raw[hopOffset:hopOffset+hopLen])
	copy(s.Raw[hopOffset:hopOffset+flyoverLen-hopLen], t[:])
	// Set and Unset Flyoverbits
	s.Raw[hopOffset-hopLen] |= 0x80
	s.Raw[hopOffset+flyoverLen-hopLen] &= 0x7f
	// Adapt Seglens and CurrHF
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF] -= 2
	s.Base.PathMeta.SegLen[s.PathMeta.CurrINF-1] += 2
	s.Base.PathMeta.CurrHF += 2
	return s.Base.PathMeta.SerializeTo(s.Raw[:])
}
