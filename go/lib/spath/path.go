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
	"crypto/rand"
	"fmt"
	"hash"
	"math"
	"math/big"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/util"
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

	// version is a temporary solution for supporting V2 paths in method calls.
	version int
	ohp     bool
}

func New(raw common.RawBytes) *Path {
	return &Path{Raw: raw}
}

func NewV2(raw []byte, ohp bool) *Path {
	return &Path{Raw: raw, version: 2, ohp: ohp}
}

// NewOneHop creates a new one hop path with. If necessary, the caller has
// to initialize the offsets.
func NewOneHop(isd addr.ISD, ifid common.IFIDType, ts time.Time, exp ExpTimeType,
	hfmac hash.Hash) *Path {

	info := InfoField{
		ConsDir: true,
		Hops:    2,
		ISD:     uint16(isd),
		TsInt:   util.TimeToSecs(ts),
	}
	hop := HopField{
		ConsEgress: ifid,
		ExpTime:    exp,
	}
	hop.Mac = hop.CalcMac(hfmac, info.TsInt, nil)
	raw := make(common.RawBytes, InfoFieldLength+2*HopFieldLength)
	info.Write(raw[:InfoFieldLength])
	hop.Write(raw[InfoFieldLength:])
	return New(raw)
}

func NewOneHopV2(isd addr.ISD, ifid common.IFIDType, ts time.Time, exp ExpTimeType,
	hfmac hash.Hash) (*Path, error) {

	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return nil, err
	}
	ohp := onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			Timestamp: util.TimeToSecs(ts),
			SegID:     uint16(segID.Uint64()),
		},
		FirstHop: path.HopField{
			ConsEgress: uint16(ifid),
			ExpTime:    uint8(exp),
		},
	}
	ohp.FirstHop.Mac = path.MAC(hfmac, &ohp.Info, &ohp.FirstHop)

	raw := make([]byte, onehop.PathLen)
	if err := ohp.SerializeTo(raw); err != nil {
		return nil, err
	}
	return &Path{
		Raw:     raw,
		version: 2,
		ohp:     true,
	}, nil
}

func (p *Path) Copy() *Path {
	if p == nil {
		return nil
	}
	return &Path{
		Raw:     append(common.RawBytes(nil), p.Raw...),
		InfOff:  p.InfOff,
		HopOff:  p.HopOff,
		version: p.version,
		ohp:     p.ohp,
	}
}

func (p *Path) reverse2() error {
	var path scion.Decoded
	if p.ohp {
		//  Since a OHP can't be reversed we create a proper SCION path instead,
		//  and reverse that.
		var ohp onehop.Path
		if err := ohp.DecodeFromBytes(p.Raw); err != nil {
			return serrors.WrapStr("decoding v2 OHP path", err)
		}
		sp, err := ohp.ToSCIONDecoded()
		if err != nil {
			return serrors.WrapStr("converting to scion path", err)
		}
		// increment the path, since we are at the receiver side.
		if err := sp.IncPath(); err != nil {
			return serrors.WrapStr("incrementing path", err)
		}
		path = *sp
		p.Raw = make([]byte, sp.Len())
		p.ohp = false
	} else {
		if err := path.DecodeFromBytes(p.Raw); err != nil {
			return err
		}
	}
	if err := path.Reverse(); err != nil {
		return err
	}
	// this clobbers paths, but anyway there's not much we can do with the path if reversal fails
	if err := path.SerializeTo(p.Raw); err != nil {
		return err
	}
	return nil
}

func (p *Path) Reverse() error {
	if p.version == 2 {
		return p.reverse2()
	}
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

// IsHeaderV2 returns whether the path is in the new format.
func (path *Path) IsHeaderV2() bool {
	return path.version == 2
}

func (path *Path) IsOHP() bool {
	return path.ohp
}

// InitOffsets computes the initial Hop Field offset (in bytes) for a newly
// created packet.
func (path *Path) InitOffsets() error {
	if path.version == 2 {
		return nil
	}
	var err error
	var infoF *InfoField
	var hopF *HopField
	path.InfOff = 0
	path.HopOff = common.LineLen
	// Cannot initialize an empty path
	if path.IsEmpty() {
		return serrors.New("Unable to initialize empty path")
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
		return serrors.New("Unable to find routing Hop Field in first path segment")
	}
	return nil
}

// IncOffsets updates the info and hop indices to the next routing field, while skipping
// verify only fields.
func (path *Path) IncOffsets() error {
	if path.version == 2 {
		panic("not supported")
	}
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
		return nil, serrors.New("Unable to get infoField from empty path")
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
		return nil, serrors.New("Unable to get hopField from empty path")
	}
	hopF, err := HopFFromRaw(path.Raw[offset:])
	if err != nil {
		return nil, common.NewBasicError("Unable to parse Hop Field", err, "offset", offset)
	}
	return hopF, nil
}

func (path *Path) String() string {
	var p string
	switch {
	case path.version == 2 && path.ohp:
		var op onehop.Path
		if err := op.DecodeFromBytes(path.Raw); err != nil {
			p = fmt.Sprintf("err decoding: %v", err)
		} else {
			p = fmt.Sprintf("{consdir: %t, 1st: %s, 2nd %s", op.Info.ConsDir,
				fmt.Sprintf("I: %d, E: %d", op.FirstHop.ConsIngress, op.FirstHop.ConsEgress),
				fmt.Sprintf("I: %d, E: %d", op.SecondHop.ConsIngress, op.SecondHop.ConsEgress))
		}
	case path.version == 2:
		var sp scion.Decoded
		if err := sp.DecodeFromBytes(path.Raw); err != nil {
			p = fmt.Sprintf("err decoding: %v", err)
		} else {
			p = fmt.Sprintf("{Meta: %s, NumINF: %d, NumHops: %d}",
				sp.PathMeta, sp.NumINF, sp.NumHops)
		}
	}
	return fmt.Sprintf("{version: %d, ohp: %t, p: %s}", path.version, path.ohp, p)
}
