// Copyright 2020 ETH Zurich
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

// Package epic implements the Path interface for the EPIC path type.
package epic

import (
	"encoding/binary"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
	// PathType denotes the EPIC path type identifier.
	PathType path.Type = 3
	// overhead denotes the number of bytes the EPIC path type contains in addition to the SCION
	// path type. It is the sum of the PacketTimestamp (8B), the PHVF (4B) and the LHVF (4B) sizes.
	overhead = 16
)

// RegisterPath registers the EPIC path type globally.
func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "Epic",
		New: func() path.Path {
			return &EpicPath{ScionRaw: &scion.Raw{}}
		},
	})
}

// EpicPath denotes the EPIC path type header.
type EpicPath struct {
	PacketTimestamp uint64
	PHVF            []byte
	LHVF            []byte
	ScionRaw        *scion.Raw
}

// SerializeTo serializes the EpicPath into buffer b. On failure, an error is returned, otherwise
// SerializeTo will return nil.
func (p *EpicPath) SerializeTo(b []byte) error {
	if p == nil {
		return serrors.New("epic path must not be nil")
	}
	if len(b) < 16 {
		return serrors.New("buffer for EpicPath too short (< 16 bytes)")
	}
	if len(p.PHVF) != 4 || len(p.LHVF) != 4 {
		return serrors.New("PHVF and LHVF must have 4 bytes",
			"PHVF", len(p.PHVF), "LHVF", len(p.LHVF))
	}
	if p.ScionRaw == nil {
		return serrors.New("scion subheader must exist")
	}
	binary.BigEndian.PutUint64(b[:8], p.PacketTimestamp)
	copy(b[8:12], p.PHVF)
	copy(b[12:16], p.LHVF)
	return p.ScionRaw.SerializeTo(b[16:])
}

// DecodeFromBytes deserializes the buffer b into the EpicPath. On failure, an error is returned,
// otherwise SerializeTo will return nil.
func (p *EpicPath) DecodeFromBytes(b []byte) error {
	if p == nil {
		return serrors.New("epic path must not be nil")
	}
	if len(b) < 16 {
		return serrors.New("EpicPath bytes too short (< 16 bytes)")
	}
	p.PacketTimestamp = binary.BigEndian.Uint64(b[:8])
	p.PHVF = make([]byte, 4)
	p.LHVF = make([]byte, 4)
	copy(p.PHVF, b[8:12])
	copy(p.LHVF, b[12:16])
	p.ScionRaw = &scion.Raw{}
	return p.ScionRaw.DecodeFromBytes(b[16:])
}

// Reverse reverses the EPIC path. In particular, this means that the SCION path type subheader
// is reversed.
func (p *EpicPath) Reverse() (path.Path, error) {
	if p == nil {
		return nil, serrors.New("epic path must not be nil")
	}
	if p.ScionRaw == nil {
		return nil, serrors.New("scion subpath must not be nil")
	}
	revScion, err := p.ScionRaw.Reverse()
	if err != nil {
		return nil, err
	}
	scionRaw, ok := revScion.(*scion.Raw)
	if !ok {
		return nil, err
	}
	p.ScionRaw = scionRaw
	return p, nil
}

// Len returns the length of the EPIC path in bytes.
func (p *EpicPath) Len() int {
	if p == nil {
		return 0
	}
	if p.ScionRaw == nil {
		return overhead
	}
	return overhead + p.ScionRaw.Len()
}

// Type returns the EPIC path type identifier.
func (p *EpicPath) Type() path.Type {
	return PathType
}
