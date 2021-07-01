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

	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	maxTimestamp = math.MaxUint32
)

var (
	// MaxExpirationTime is the maximum absolute expiration time of SCION hop
	// fields.
	MaxExpirationTime = time.Unix(maxTimestamp, 0).Add(path.ExpTimeToDuration(math.MaxUint8))
)

// Path is the raw dataplane path.
type Path struct {
	Raw      []byte
	Type     path.Type
	EpicData EpicData
}

type EpicData struct {
	enabled  bool
	AuthPHVF []byte
	AuthLHVF []byte
	Counter  uint32
}

// NewOneHop creates a onehop path that has the first hopfield initialized.
func NewOneHop(egress uint16, timestamp time.Time, expiration uint8, mac hash.Hash) (Path, error) {
	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return Path{}, err
	}
	ohp := onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			Timestamp: util.TimeToSecs(timestamp),
			SegID:     uint16(segID.Uint64()),
		},
		FirstHop: path.HopField{
			ConsEgress: egress,
			ExpTime:    expiration,
		},
	}
	ohp.FirstHop.Mac = path.MAC(mac, &ohp.Info, &ohp.FirstHop, nil)

	raw := make([]byte, onehop.PathLen)
	if err := ohp.SerializeTo(raw); err != nil {
		return Path{}, err
	}
	return Path{
		Raw:  raw,
		Type: onehop.PathType,
	}, nil
}

func (p Path) IsEmpty() bool {
	return len(p.Raw) == 0 && p.Type == empty.PathType
}

func (p Path) Copy() Path {
	return Path{
		Raw:      append(p.Raw[:0:0], p.Raw...),
		Type:     p.Type,
		EpicData: p.EpicData,
	}
}

func (p Path) SupportsEpic() bool {
	if len(p.EpicData.AuthPHVF) != libepic.AuthLen {
		return false
	}
	if len(p.EpicData.AuthLHVF) != libepic.AuthLen {
		return false
	}
	return true
}

func (p Path) EpicEnabled() bool {
	return p.EpicData.enabled
}

func (p *Path) EnableEpic() error {
	if p.SupportsEpic() {
		p.EpicData.enabled = true
		return nil
	}
	return serrors.New("EPIC not supported")
}

func (p *Path) AddEpicPktID(ep *epic.Path) error {
	info, err := ep.ScionPath.GetInfoField(0)
	if err != nil {
		return err
	}
	tsInfo := time.Unix(int64(info.Timestamp), 0)
	timestamp, err := libepic.CreateTimestamp(tsInfo, time.Now())
	if err != nil {
		return err
	}
	p.EpicData.Counter = p.EpicData.Counter + 1
	ep.PktID = epic.PktID{
		Timestamp: timestamp,
		Counter:   p.EpicData.Counter,
	}
	return nil
}

func (p Path) AddEpicHVFs(ep *epic.Path, s *slayers.SCION) error {
	info, err := ep.ScionPath.GetInfoField(0)
	if err != nil {
		return err
	}
	phvf, err := libepic.CalcMac(p.EpicData.AuthPHVF, ep.PktID, s, info.Timestamp, nil)
	if err != nil {
		return err
	}
	lhvf, err := libepic.CalcMac(p.EpicData.AuthLHVF, ep.PktID, s, info.Timestamp, nil)
	if err != nil {
		return err
	}

	ep.PHVF = phvf[:epic.HVFLen]
	ep.LHVF = lhvf[:epic.HVFLen]
	return nil
}

func (p *Path) Reverse() error {
	if p == nil || len(p.Raw) == 0 {
		// Empty path doesn't need reversal.
		return nil
	}
	po, err := path.NewPath(p.Type)
	if err != nil {
		return err
	}
	if err := po.DecodeFromBytes(p.Raw); err != nil {
		return err
	}
	po, err = po.Reverse()
	if err != nil {
		return err
	}

	// On the EPIC return path, use the SCION path type
	if p.Type == epic.PathType {
		e, ok := po.(*epic.Path)
		if !ok {
			return serrors.New("Path type and path data do not match")
		}
		po = e.ScionPath
		p.EpicData.enabled = false
	}

	p.Type = po.Type()
	l := po.Len()
	if l > len(p.Raw) {
		p.Raw = make([]byte, l)
	}
	p.Raw = p.Raw[:l]
	// this clobbers paths, but anyway there's not much we can do with the path
	// if reversal fails
	if err := po.SerializeTo(p.Raw); err != nil {
		return err
	}
	return nil
}

func (path *Path) IsOHP() bool {
	return path.Type == onehop.PathType
}

func (path *Path) String() string {
	var p string
	switch path.Type {
	case onehop.PathType:
		var op onehop.Path
		if err := op.DecodeFromBytes(path.Raw); err != nil {
			p = fmt.Sprintf("err decoding: %v", err)
		} else {
			p = fmt.Sprintf("{consdir: %t, 1st: %s, 2nd %s", op.Info.ConsDir,
				fmt.Sprintf("I: %d, E: %d", op.FirstHop.ConsIngress, op.FirstHop.ConsEgress),
				fmt.Sprintf("I: %d, E: %d", op.SecondHop.ConsIngress, op.SecondHop.ConsEgress))
		}
	case scion.PathType:
		var sp scion.Decoded
		if err := sp.DecodeFromBytes(path.Raw); err != nil {
			p = fmt.Sprintf("err decoding: %v", err)
		} else {
			p = fmt.Sprintf("{Meta: %s, NumINF: %d, NumHops: %d}",
				sp.PathMeta, sp.NumINF, sp.NumHops)
		}
	default:
		p = "not supported"
	}
	return fmt.Sprintf("{type: %s, p: %s}", path.Type, p)
}
