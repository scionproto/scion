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

package control_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/router/control"
)

func TestLoad(t *testing.T) {
	tests := map[string]struct {
		ExpectedTopo func(t *testing.T) topology.Topology
	}{
		"base": {
			ExpectedTopo: func(t *testing.T) topology.Topology {
				expectedTopo, err := topology.FromJSONFile("testdata/topology.json")
				require.NoError(t, err)
				return expectedTopo
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := control.LoadConfig("br1-ff00_0_110-2", "testdata")
			assert.NoError(t, err)
			assert.NotNil(t, c)
			expectedTopo := test.ExpectedTopo(t)
			assert.Equal(t, expectedTopo, c.Topo)
		})
	}
}
