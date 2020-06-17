// Copyright 2020 ETH Zurich, Anapaya Systems
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

package segment

import (
	"encoding/binary"
	"io"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Path represents a reservation path, in the reservation order.
type Path []PathStepWithIA

var _ io.Reader = (*Path)(nil)

// NewPathFromRaw constructs a new Path from the byte representation.
func NewPathFromRaw(buff []byte) Path {
	steps := len(buff) / PathStepWithIALen
	p := make(Path, steps)
	for i := 0; i < steps; i++ {
		offset := i * PathStepWithIALen
		p[i].Ingress = common.IFIDType(binary.BigEndian.Uint64(buff[offset:]))
		p[i].Egress = common.IFIDType(binary.BigEndian.Uint64(buff[offset+8:]))
		p[i].IA = addr.IAFromRaw(buff[offset+16:])
	}
	return p
}

// Validate returns an error if there is invalid data.
func (p Path) Validate() error {
	if len(p) < 2 {
		return serrors.New("invalid path length", "len", len(p))
	}
	if p[0].Ingress != 0 {
		return serrors.New("wrong ingress interface for source", "ingress", p[0].Ingress)
	}
	if p[len(p)-1].Egress != 0 {
		return serrors.New("wrong egress interface for destination",
			"egress ID", p[len(p)-1].Ingress)
	}
	return nil
}

// Equal returns true if both Path contain the same values.
func (p Path) Equal(o Path) bool {
	if len(p) != len(o) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !p[i].Equal(&o[i]) {
			return false
		}
	}
	return true
}

// GetSrcIA returns the source IA in the path or a zero IA if the path is nil (it's not the
// source AS of the reservation and has no access to the Path of the reservation).
// If the Path is not nil, it assumes is valid, i.e. it has at least length 2.
func (p *Path) GetSrcIA() addr.IA {
	if p == nil {
		return addr.IA{}
	}
	return (*p)[0].IA
}

// GetDstIA returns the source IA in the path or a zero IA if the path is nil (it's not the
// source AS of the reservation and has no access to the Path of the reservation).
// If the Path is not nil, it assumes is valid, i.e. it has at least length 2.
func (p *Path) GetDstIA() addr.IA {
	if p == nil {
		return addr.IA{}
	}
	return (*p)[len(*p)-1].IA
}

// Len returns the length of this Path in bytes, when serialized.
func (p *Path) Len() int {
	if p == nil {
		return 0
	}
	return len(*p) * PathStepWithIALen
}

func (p *Path) Read(buff []byte) (int, error) {
	if p == nil {
		return 0, nil
	}
	if len(buff) < p.Len() {
		return 0, serrors.New("buffer too small", "min_size", p.Len(), "actual_size", len(buff))
	}
	for i, s := range *p {
		offset := i * PathStepWithIALen
		binary.BigEndian.PutUint64(buff[offset:], uint64(s.Ingress))
		binary.BigEndian.PutUint64(buff[offset+8:], uint64(s.Egress))
		binary.BigEndian.PutUint64(buff[offset+16:], uint64(s.IA.IAInt()))
	}
	return p.Len(), nil
}

// ToRaw returns a buffer representing this Path.
func (p *Path) ToRaw() []byte {
	if p == nil {
		return []byte{}
	}
	buff := make([]byte, p.Len())
	p.Read(buff)
	return buff
}

// PathStep is one hop of the Path. For a source AS Ingress will be invalid. Conversely for dst.
type PathStep struct {
	Ingress common.IFIDType
	Egress  common.IFIDType
}

// Equal returns true if both PathStep variables contain the same values, or both nil.
func (s *PathStep) Equal(o *PathStep) bool {
	if s == o {
		return true
	}
	return s.Ingress == o.Ingress && s.Egress == o.Egress
}

// PathStepWithIA is a step in a reservation path as seen from the source AS.
type PathStepWithIA struct {
	PathStep
	IA addr.IA
}

// PathStepWithIALen amounts for Ingress+Egress+IA.
const PathStepWithIALen = 8 + 8 + 8

// Equal returns true if both PathStep variables contain the same values, or both nil.
func (s *PathStepWithIA) Equal(o *PathStepWithIA) bool {
	if s == o {
		return true
	}
	return s.PathStep.Equal(&o.PathStep) && s.IA == o.IA
}
