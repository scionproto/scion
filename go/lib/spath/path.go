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
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
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
	Type slayers.PathType
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
		Type: slayers.PathTypeOneHop,
	}, nil
}

func (p Path) IsEmpty() bool {
	return len(p.Raw) == 0 && p.Type == slayers.PathTypeEmpty
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
	var path scion.Decoded
	switch p.Type {
	case slayers.PathTypeSCION:
		if err := path.DecodeFromBytes(p.Raw); err != nil {
			return err
		}
	case slayers.PathTypeOneHop:
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
		p.Type = slayers.PathTypeSCION
	default:
		return serrors.New("unsupported path", "type", p.Type)
	}
	if err := path.Reverse(); err != nil {
		return err
	}
	// this clobbers paths, but anyway there's not much we can do with the path
	// if reversal fails
	if err := path.SerializeTo(p.Raw); err != nil {
		return err
	}
	return nil
}

func (path *Path) IsOHP() bool {
	return path.Type == slayers.PathTypeOneHop
}

func (path *Path) String() string {
	var p string
	switch path.Type {
	case slayers.PathTypeOneHop:
		var op onehop.Path
		if err := op.DecodeFromBytes(path.Raw); err != nil {
			p = fmt.Sprintf("err decoding: %v", err)
		} else {
			p = fmt.Sprintf("{consdir: %t, 1st: %s, 2nd %s", op.Info.ConsDir,
				fmt.Sprintf("I: %d, E: %d", op.FirstHop.ConsIngress, op.FirstHop.ConsEgress),
				fmt.Sprintf("I: %d, E: %d", op.SecondHop.ConsIngress, op.SecondHop.ConsEgress))
		}
	case slayers.PathTypeSCION:
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
