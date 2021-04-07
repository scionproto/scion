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
	// MetadataLen denotes the number of bytes the EPIC path type contains in addition to the SCION
	// path type. It is the sum of the PktID (8B), the PHVF (4B) and the LHVF (4B) sizes.
	MetadataLen = 16
	// PktIDLen denotes the length of the packet identifier.
	PktIDLen = 8
	// HVFLen denotes the length of the hop validation fields. The length is the same for both the
	// PHVF and the LHVF.
	HVFLen = 4
)

// RegisterPath registers the EPIC path type globally.
func RegisterPath() {
	path.RegisterPath(path.Metadata{
		Type: PathType,
		Desc: "Epic",
		New: func() path.Path {
			return &Path{ScionPath: &scion.Raw{}}
		},
	})
}

// Path denotes the EPIC path type header.
type Path struct {
	PktID     PktID
	PHVF      []byte
	LHVF      []byte
	ScionPath *scion.Raw
}

// SerializeTo serializes the Path into buffer b. On failure, an error is returned, otherwise
// SerializeTo will return nil.
func (p *Path) SerializeTo(b []byte) error {
	if len(b) < p.Len() {
		return serrors.New("buffer too small to serialize path.", "expected", p.Len(),
			"actual", len(b))
	}
	if len(p.PHVF) != HVFLen {
		return serrors.New("invalid length of PHVF", "expected", HVFLen, "actual", len(p.PHVF))
	}
	if len(p.LHVF) != HVFLen {
		return serrors.New("invalid length of LHVF", "expected", HVFLen, "actual", len(p.LHVF))
	}
	if p.ScionPath == nil {
		return serrors.New("SCION path is nil")
	}
	p.PktID.SerializeTo(b[:PktIDLen])
	copy(b[PktIDLen:(PktIDLen+HVFLen)], p.PHVF)
	copy(b[(PktIDLen+HVFLen):MetadataLen], p.LHVF)
	return p.ScionPath.SerializeTo(b[MetadataLen:])
}

// DecodeFromBytes deserializes the buffer b into the Path. On failure, an error is returned,
// otherwise SerializeTo will return nil.
func (p *Path) DecodeFromBytes(b []byte) error {
	if len(b) < MetadataLen {
		return serrors.New("EPIC Path raw too short", "expected", MetadataLen, "actual", len(b))
	}
	p.PktID.DecodeFromBytes(b[:PktIDLen])
	p.PHVF = make([]byte, HVFLen)
	p.LHVF = make([]byte, HVFLen)
	copy(p.PHVF, b[PktIDLen:(PktIDLen+HVFLen)])
	copy(p.LHVF, b[(PktIDLen+HVFLen):MetadataLen])
	p.ScionPath = &scion.Raw{}
	return p.ScionPath.DecodeFromBytes(b[MetadataLen:])
}

// Reverse reverses the EPIC path. In particular, this means that the SCION path type subheader
// is reversed.
func (p *Path) Reverse() (path.Path, error) {
	if p.ScionPath == nil {
		return nil, serrors.New("scion subpath must not be nil")
	}
	revScion, err := p.ScionPath.Reverse()
	if err != nil {
		return nil, err
	}
	ScionPath, ok := revScion.(*scion.Raw)
	if !ok {
		return nil, err
	}
	p.ScionPath = ScionPath
	return p, nil
}

// Len returns the length of the EPIC path in bytes.
func (p *Path) Len() int {
	if p.ScionPath == nil {
		return MetadataLen
	}
	return MetadataLen + p.ScionPath.Len()
}

// Type returns the EPIC path type identifier.
func (p *Path) Type() path.Type {
	return PathType
}

// PktID denotes the EPIC packet ID.
type PktID struct {
	Timestamp uint32
	Counter   uint32
}

// DecodeFromBytes deserializes the buffer (raw) into the PktID.
func (i *PktID) DecodeFromBytes(raw []byte) {
	i.Timestamp = binary.BigEndian.Uint32(raw[:4])
	i.Counter = binary.BigEndian.Uint32(raw[4:8])
}

// SerializeTo serializes the PktID into the buffer (b).
func (i *PktID) SerializeTo(b []byte) {
	binary.BigEndian.PutUint32(b[:4], i.Timestamp)
	binary.BigEndian.PutUint32(b[4:8], i.Counter)
}
