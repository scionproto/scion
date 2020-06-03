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
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Path represents a reservation path, in the reservation order.
type Path []PathStepWithIA

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

// PathStep is one hop of the Path. For a source AS Ingress will be invalid. Conversely for dst.
type PathStep struct {
	// IA      addr.IA
	Ingress common.IFIDType
	Egress  common.IFIDType
}

func (s *PathStep) Equal(o *PathStep) bool {
	// return s.IA == o.IA && s.Ingress == o.Ingress && s.Egress == o.Egress
	return s.Ingress == o.Ingress && s.Egress == o.Egress
}

type PathStepWithIA struct {
	PathStep
	IA addr.IA
}

func (s *PathStepWithIA) Equal(o *PathStepWithIA) bool {
	return s.PathStep.Equal(&o.PathStep) && s.IA == o.IA
}
