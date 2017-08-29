// Copyright 2016 ETH Zurich
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
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
)

const (
	MaxTTL      = 24 * 60 * 60 // One day in seconds
	ExpTimeUnit = MaxTTL / 2 << 8
	macInputLen = 16
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

func (p *Path) Reverse() *common.Error {
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
			return common.NewError("Unable to reverse corrupt path",
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
		infoF.Up = !infoF.Up // Reverse Up flag
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
	if path == nil || len(path.Raw) == 0 {
		return common.NewError("Unable to initialize empty path")
	}

	// Skip Peer with Xover HF
	if infoF, err = path.getInfoField(path.InfOff); err != nil {
		return err
	}
	if infoF.Peer {
		if hopF, err = path.getHopField(path.HopOff); err != nil {
			return err
		}
		if hopF.Xover {
			path.HopOff += hopF.Len()
		}
	}
	err = path.incOffsets(0)
	if err != nil {
		return err
	}
	if path.InfOff != 0 {
		return common.NewError("Unable to find routing Hop Field in first path" +
			"segment")
	}
	return nil
}

// IncOffsets updates the info and hop indices to the next routing field, while skipping
// verify only fields.
func (path *Path) IncOffsets() error {
	var hopF *HopField
	var err error
	if path.HopOff == 0 {
		// Path not initialized yet
		return path.InitOffsets()
	}
	if hopF, err = path.getHopField(path.HopOff); err != nil {
		return common.NewError("Hop Field parse error",
			"offset", path.HopOff, "err", err)
	}
	return path.incOffsets(hopF.Len())
}

// incOffsets jumps ahead skip bytes, and searches for the first routing Hop
// Field starting at that location
func (path *Path) incOffsets(skip int) error {
	var hopF *HopField
	infoF, err := path.getInfoField(path.InfOff)
	if err != nil {
		return common.NewError("Info Field parse error", "offset", path.InfOff,
			"err", err)
	}

	path.HopOff += skip
	for {
		if path.HopOff-path.InfOff > int(infoF.Hops)*common.LineLen {
			// Switch to next segment
			path.InfOff = path.HopOff
			infoF, err = path.getInfoField(path.InfOff)
			if err != nil {
				return common.NewError("Info Field parse error",
					"offset", path.InfOff, "err", err)
			}
			path.HopOff += common.LineLen
		}

		if hopF, err = path.getHopField(path.HopOff); err != nil {
			return common.NewError("Hop Field parse error",
				"offset", path.HopOff, "err", err)
		}
		if !hopF.VerifyOnly {
			break
		}
		path.HopOff += hopF.Len()
	}
	return nil
}

func (path *Path) getInfoField(offset int) (*InfoField, error) {
	if offset < 0 {
		return nil, common.NewError("Negative offset", "offset", offset)
	}
	infoF, cerr := InfoFFromRaw(path.Raw[offset:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Info Field", "err", cerr)
	}
	return infoF, nil
}

func (path *Path) getHopField(offset int) (*HopField, error) {
	if offset < 0 {
		return nil, common.NewError("Negative offset", "offset", offset)
	}
	hopF, cerr := HopFFromRaw(path.Raw[offset:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Hop Field", "err", cerr)
	}
	return hopF, nil
}
