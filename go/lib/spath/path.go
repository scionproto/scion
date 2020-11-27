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
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
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
	Raw  []byte
	Type path.Type
}

func NewOneHop(isd addr.ISD, ifID uint16, ts time.Time, exp uint8, hfmac hash.Hash) (Path, error) {
	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return Path{}, err
	}
	ohp := onehop.Path{
		Info: path.InfoField{
			ConsDir:   true,
			Timestamp: util.TimeToSecs(ts),
			SegID:     uint16(segID.Uint64()),
		},
		FirstHop: path.HopField{
			ConsEgress: ifID,
			ExpTime:    exp,
		},
	}
	ohp.FirstHop.Mac = path.MAC(hfmac, &ohp.Info, &ohp.FirstHop)

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
		Raw:  append(p.Raw[:0:0], p.Raw...),
		Type: p.Type,
	}
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
