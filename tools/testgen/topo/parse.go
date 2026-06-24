// Copyright 2026 Anapaya Systems
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

package topo

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// ParseFile reads and YAML-decodes a topology description file. It does not
// validate the result; call [Validate] separately.
func ParseFile(path string) (*Topo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, serrors.Wrap("reading topology file", err, "path", path)
	}
	return Parse(raw)
}

// Parse YAML-decodes a topology description.
func Parse(raw []byte) (*Topo, error) {
	var t Topo
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, serrors.Wrap("decoding topology", err)
	}
	if t.ASes == nil {
		t.ASes = map[addr.IA]ASEntry{}
	}
	return &t, nil
}
