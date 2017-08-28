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

import
//log "github.com/inconshreveable/log15"

"github.com/netsec-ethz/scion/go/lib/common"

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

// InitHopOffset computes the initial hopOffset (in bytes) for a newly created
// packet.
func (path *Path) InitHopOffset() (int, error) {
	var err error
	var infoF *InfoField
	var hopF *HopField
	infoOffset, hopOffset := 0, common.LineLen

	// Cannot initialize an empty path
	if path == nil {
		return 0, common.NewError("Unable to initialize empty path")
	}

	// Skip Peer with Xover HF
	if infoF, err = path.getInfoField(infoOffset); err != nil {
		return 0, err
	}
	if infoF.Peer {
		if hopF, err = path.getHopField(hopOffset); err != nil {
			return 0, err
		}
		if hopF.Xover {
			hopOffset += hopF.Len()
		}
	}

	newInfoOffset, newHopOffset, err := path.IncOffsets(infoOffset, hopOffset)
	if err != nil {
		return 0, err
	}
	if newInfoOffset != 0 {
		return 0, common.NewError("Unable to find routing Hop Field in first path" +
			"segment")
	}

	return newHopOffset, nil
}

// InfOffsets returns the info and hop indices for the next routing field, while skipping
// verify only fields.
func (path *Path) IncOffsets(curInfoOff, curHopOff int) (newInfoOff, newHopOff int, err error) {
	var hopF *HopField
	infoF, err := path.getInfoField(curInfoOff)
	if err != nil {
		return 0, 0, common.NewError("Info Field parse error", "offset",
			curInfoOff)
	}

	for {
		if curHopOff-curInfoOff > int(infoF.Hops)*common.LineLen {
			// Go to next Info
			curInfoOff = curHopOff
			infoF, err = path.getInfoField(curInfoOff)
			if err != nil {
				return 0, 0, common.NewError("Info Field parse error",
					"offset", curInfoOff)
			}
			curHopOff += common.LineLen
		}

		if hopF, err = path.getHopField(curHopOff); err != nil {
			return 0, 0, common.NewError("Hop Field parse error",
				"offset", curHopOff)
		}
		if !hopF.VerifyOnly {
			break
		}

		curHopOff += hopF.Len()
	}
	return curInfoOff, curHopOff, nil
}

func (path *Path) getInfoField(index int) (*InfoField, error) {
	if index < 0 {
		return nil, common.NewError("Negative index", "index", index)
	}
	infoF, cerr := InfoFFromRaw(path.Raw[index:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Info Field", "err", cerr)
	}
	return infoF, nil
}

func (path *Path) getHopField(index int) (*HopField, error) {
	if index < 0 {
		return nil, common.NewError("Negative index", "index", index)
	}
	hopF, cerr := HopFFromRaw(path.Raw[index:])
	if cerr != nil {
		return nil, common.NewError("Unable to parse Hop Field", "err", cerr)
	}
	return hopF, nil
}
