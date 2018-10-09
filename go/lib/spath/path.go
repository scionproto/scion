// Copyright 2016 ETH Zurich
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

package spath

import (
	"math"
	"time"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	MaxTimestamp = math.MaxUint32
)

var (
	// MaxExpirationTime is the maximum absolute expiration time of SCION hop
	// fields.
	MaxExpirationTime = time.Unix(MaxTimestamp, 0).Add(MaxTTLField.ToDuration())
)

type Path struct {
	Raw    common.RawBytes
	InfOff int // Offset of current Info Field
	HopOff int // Offset of current Hop Field
}

func New(raw common.RawBytes) *Path {
	return &Path{Raw: raw}
}

func (p *Path) Copy() *Path {
	return &Path{append(common.RawBytes(nil), p.Raw...), p.InfOff, p.HopOff}
}

func (p *Path) Reverse() error {
	if len(p.Raw) == 0 {
		// Empty path doesn't need reversal.
		return nil
	}
	var infOffs = make([]int, 0, 3)       // Indexes of Info Fields
	var infoFs = make([]*InfoField, 0, 3) // Info Fields
	var origOff = 0
	// First pass: parse Info Fields and save offsets.
	for i := 0; i < 3; i++ {
		infOffs = append(infOffs, origOff)
		infoF, err := InfoFFromRaw(p.Raw[origOff:])
		if err != nil {
			return err
		}
		infoFs = append(infoFs, infoF)
		origOff += InfoFieldLength + int(infoF.Hops)*HopFieldLength
		if origOff == len(p.Raw) {
			break
		} else if origOff > len(p.Raw) {
			return common.NewBasicError("Unable to reverse corrupt path", nil,
				"currOff", origOff, "max", len(p.Raw))
		}
	}
	revRaw := make(common.RawBytes, len(p.Raw))
	revOff := 0
	newInfIdx := 0
	switch {
	case p.InfOff == 0:
		newInfIdx = len(infOffs) - 1
	case p.InfOff == infOffs[len(infOffs)-1]:
		newInfIdx = 0
	default:
		newInfIdx = 1
	}
	idx := 0
	// Fill in reversed path, starting with last segment.
	for i := len(infoFs) - 1; i >= 0; i-- {
		if idx == newInfIdx {
			p.InfOff = revOff
		}
		infoF := infoFs[i]
		infoF.ConsDir = !infoF.ConsDir // Reverse ConsDir flag
		infoF.Write(revRaw[revOff:])
		infoF, _ = InfoFFromRaw(revRaw[revOff:])
		revOff += InfoFieldLength
		hOffBase := infOffs[i] + InfoFieldLength
		// Copy segment Hop Fields in reverse.
		for j := int(infoF.Hops) - 1; j >= 0; j-- {
			hOff := hOffBase + j*HopFieldLength
			copy(revRaw[revOff:], p.Raw[hOff:hOff+HopFieldLength])
			revOff += HopFieldLength
		}
		idx++
	}
	// Calculate Hop Field offset.
	p.HopOff = len(p.Raw) - p.HopOff
	// Update path with reversed copy.
	p.Raw = revRaw
	return nil
}

// InitOffsets computes the initial Hop Field offset (in bytes) for a newly
// created packet.
func (path *Path) InitOffsets() error {
	var err error
	var infoF *InfoField
	var hopF *HopField
	path.InfOff = 0
	path.HopOff = common.LineLen
	// Cannot initialize an empty path
	if path.IsEmpty() {
		return common.NewBasicError("Unable to initialize empty path", nil)
	}
	// Skip Peer with Xover HF
	if infoF, err = path.GetInfoField(path.InfOff); err != nil {
		return err
	}
	if infoF.Peer {
		if hopF, err = path.GetHopField(path.HopOff); err != nil {
			return err
		}
		if hopF.Xover {
			path.HopOff += HopFieldLength
		}
	}
	err = path.incOffsets(0)
	if err != nil {
		return err
	}
	if path.InfOff != 0 {
		return common.NewBasicError("Unable to find routing Hop Field in first path segment", nil)
	}
	return nil
}

// IncOffsets updates the info and hop indices to the next routing field, while skipping
// verify only fields.
func (path *Path) IncOffsets() error {
	var err error
	if path.HopOff == 0 {
		// Path not initialized yet
		return path.InitOffsets()
	}
	if _, err = path.GetHopField(path.HopOff); err != nil {
		return common.NewBasicError("Hop Field parse error", err, "offset", path.HopOff)
	}
	return path.incOffsets(HopFieldLength)
}

// IsEmpty returns true if the path is nil or empty (no raw data).
func (path *Path) IsEmpty() bool {
	return path == nil || len(path.Raw) == 0
}

// incOffsets jumps ahead skip bytes, and searches for the first routing Hop
// Field starting at that location
func (path *Path) incOffsets(skip int) error {
	var hopF *HopField
	infoF, err := path.GetInfoField(path.InfOff)
	if err != nil {
		return common.NewBasicError("Info Field parse error", err, "offset", path.InfOff)
	}
	path.HopOff += skip
	for {
		if path.HopOff-path.InfOff > int(infoF.Hops)*common.LineLen {
			// Switch to next segment
			path.InfOff = path.HopOff
			infoF, err = path.GetInfoField(path.InfOff)
			if err != nil {
				return common.NewBasicError("Info Field parse error", err, "offset", path.InfOff)
			}
			path.HopOff += common.LineLen
		}
		if hopF, err = path.GetHopField(path.HopOff); err != nil {
			return common.NewBasicError("Hop Field parse error", err, "offset", path.HopOff)
		}
		if !hopF.VerifyOnly {
			break
		}
		path.HopOff += HopFieldLength
	}
	return nil
}

func (path *Path) GetInfoField(offset int) (*InfoField, error) {
	if offset < 0 {
		return nil, common.NewBasicError("Negative InfoF offset", nil, "offset", offset)
	}
	if path.IsEmpty() {
		return nil, common.NewBasicError("Unable to get infoField from empty path", nil)
	}
	infoF, err := InfoFFromRaw(path.Raw[offset:])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse Info Field", err, "offset", offset)
	}
	return infoF, nil
}

func (path *Path) GetHopField(offset int) (*HopField, error) {
	if offset < 0 {
		return nil, common.NewBasicError("Negative HopF offset", nil, "offset", offset)
	}
	if path.IsEmpty() {
		return nil, common.NewBasicError("Unable to get hopField from empty path", nil)
	}
	hopF, err := HopFFromRaw(path.Raw[offset:])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse Hop Field", err, "offset", offset)
	}
	return hopF, nil
}
