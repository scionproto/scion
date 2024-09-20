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

package testcrypto

import (
	"os"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// topo contains the relevant part of the topo file for the testcrypto command.
type topo struct {
	ASes map[addr.IA]struct {
		CA            addr.IA `yaml:"cert_issuer"`
		Authoritative bool    `yaml:"authoritative"`
		Core          bool    `yaml:"core"`
		Issuing       bool    `yaml:"issuing"`
		Voting        bool    `yaml:"voting"`
	} `yaml:"ASes"`
}

// loadTopo loads the topo from file.
func loadTopo(file string) (topo, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return topo{}, serrors.Wrap("failed to load topofile", err, "file", file)
	}
	var t topo
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return topo{}, serrors.Wrap("failed to parse topofile", err, "file", file)
	}
	for ia, v := range t.ASes {
		if v.Issuing {
			// If an AS is issuer, it issues for itself.
			v.CA = ia
			t.ASes[ia] = v
		}
	}
	return t, nil
}
