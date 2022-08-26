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

package onehop

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

// PathLen is the length of a serialized one hop path in bytes.
const PathLen = path.InfoLen + 2*path.HopLen

const PathType path.Type = 2

func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "OneHop",
		New: func() path.Path {
			return &Path{}
		},
	})
}

// Path encodes a one hop path. A one hop path is a special path that is created by a SCION router
// in the first AS and completed by a SCION router in the second AS. It is used during beaconing
// when there is not yet any other path segment available.
type Path struct {
	Info      path.InfoField
	FirstHop  path.HopField
	SecondHop path.HopField
}

func (o *Path) DecodeFromBytes(data []byte) error {
	if len(data) < PathLen {
		return serrors.New("buffer too short for OneHop path", "expected", PathLen, "actual",
			len(data))
	}
	offset := 0
	if err := o.Info.DecodeFromBytes(data[:path.InfoLen]); err != nil {
		return err
	}
	offset += path.InfoLen
	if err := o.FirstHop.DecodeFromBytes(data[offset : offset+path.HopLen]); err != nil {
		return err
	}
	offset += path.HopLen
	return o.SecondHop.DecodeFromBytes(data[offset : offset+path.HopLen])
}

func (o *Path) SerializeTo(b []byte) error {
	if len(b) < PathLen {
		return serrors.New("buffer too short for OneHop path", "expected", PathLen, "actual",
			len(b))
	}
	offset := 0
	if err := o.Info.SerializeTo(b[:offset+path.InfoLen]); err != nil {
		return err
	}
	offset += path.InfoLen
	if err := o.FirstHop.SerializeTo(b[offset : offset+path.HopLen]); err != nil {
		return err
	}
	offset += path.HopLen
	return o.SecondHop.SerializeTo(b[offset : offset+path.HopLen])
}

// ToSCIONDecoded converts the one hop path in to a normal SCION path in the
// decoded format.
func (o *Path) ToSCIONDecoded() (*scion.Decoded, error) {
	if o.SecondHop.ConsIngress == 0 {
		return nil, serrors.New("incomplete path can't be converted")
	}
	p := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 0, 0},
			},
			NumHops: 2,
			NumINF:  1,
		},
		InfoFields: []path.InfoField{
			{
				ConsDir:   true,
				SegID:     o.Info.SegID,
				Timestamp: o.Info.Timestamp,
			},
		},
		HopFields: []path.HopField{
			{
				IngressRouterAlert: o.FirstHop.IngressRouterAlert,
				EgressRouterAlert:  o.FirstHop.EgressRouterAlert,
				ConsIngress:        o.FirstHop.ConsIngress,
				ConsEgress:         o.FirstHop.ConsEgress,
				ExpTime:            o.FirstHop.ExpTime,
				Mac:                o.FirstHop.Mac,
			},
			{
				IngressRouterAlert: o.SecondHop.IngressRouterAlert,
				EgressRouterAlert:  o.SecondHop.EgressRouterAlert,
				ConsIngress:        o.SecondHop.ConsIngress,
				ConsEgress:         o.SecondHop.ConsEgress,
				ExpTime:            o.SecondHop.ExpTime,
				Mac:                o.SecondHop.Mac,
			},
		},
	}
	return p, nil
}

// Rerverse a OneHop path that returns a reversed SCION path.
func (o *Path) Reverse() (path.Path, error) {
	sp, err := o.ToSCIONDecoded()
	if err != nil {
		return nil, serrors.WrapStr("converting to scion path", err)
	}
	// increment the path, since we are at the receiver side.
	if err := sp.IncPath(); err != nil {
		return nil, serrors.WrapStr("incrementing path", err)
	}
	return sp.Reverse()
}

func (o *Path) Len() int {
	return PathLen
}

func (o *Path) Type() path.Type {
	return PathType
}
