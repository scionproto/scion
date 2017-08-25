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

// InitHopIdx computes the initial hopIdx for a newly created packet
func (path *Path) InitHopIdx() (uint8, error) {
	var err error
	var infoF *InfoField
	var hopF *HopField
	infoIdx, hopIdx := 0, 0

	// Cannot initialize an empty path
	if path == nil {
		return 0, common.NewError("Unable to initialize empty path")
	}

	// Skip Peer with Xover HF
	if infoF, err = path.getInfoField(infoIdx); err != nil {
		return 0, err
	}
	if infoF.Peer {
		if hopF, err = path.getHopField(1); err != nil {
			return 0, err
		}
		if hopF.Xover {
			hopIdx += 1
		}
	}

	// The first HF for end-host paths is always in the first segment
	maxHopIdx := int(infoF.Hops)

	for {
		// Skip verification HFs
		hopIdx += 1
		if hopIdx > maxHopIdx {
			return 0, common.NewError("Skipped entire path segment",
				"hopIdx", hopIdx, "maxHopIdx", maxHopIdx)
		}

		if hopF, err = path.getHopField(hopIdx); err != nil {
			return 0, err
		}
		if !hopF.VerifyOnly {
			break
		}
	}
	return uint8(hopIdx), nil
}

func (path *Path) getInfoField(index int) (*InfoField, error) {
	if index < 0 {
		return nil, common.NewError("Negative index", "index", index)
	}
	infoF, cerr := InfoFFromRaw(path.Raw[index*common.LineLen:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Info Field", "err", cerr)
	}
	return infoF, nil
}

func (path *Path) getHopField(index int) (*HopField, error) {
	if index < 0 {
		return nil, common.NewError("Negative index", "index", index)
	}
	hopF, cerr := HopFFromRaw(path.Raw[index*common.LineLen:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Hop Field", "err", cerr)
	}
	return hopF, nil
}
