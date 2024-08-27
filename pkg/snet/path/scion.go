// Copyright 2021 ETH Zurich
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

package path

import (
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

type SCION struct {
	// Raw is the raw representation of this path. This data should not be
	// modified because it is potentially shared.
	Raw []byte
}

// NewSCIONFromDecoded serializes the decoded SCION path into a dataplane path.
func NewSCIONFromDecoded(d scion.Decoded) (SCION, error) {
	buf := make([]byte, d.Len())
	if err := d.SerializeTo(buf); err != nil {
		return SCION{}, serrors.Wrap("serializing decoded SCION path", err)
	}
	return SCION{Raw: buf}, nil
}

func (p SCION) SetPath(s *slayers.SCION) error {
	var sp scion.Raw
	if err := sp.DecodeFromBytes(p.Raw); err != nil {
		return err
	}
	s.Path, s.PathType = &sp, sp.Type()
	return nil
}
