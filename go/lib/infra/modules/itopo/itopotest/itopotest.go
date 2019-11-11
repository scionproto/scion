// Copyright 2019 ETH Zurich
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

package itopotest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/topology"
)

// TestTopoProvider is a provider for a specific topology object.
type TestTopoProvider struct {
	*topology.Topo
}

// TopoProviderFromFile creates a topo provider from a topology file.
// It fails the test if loading the file fails.
func TopoProviderFromFile(t *testing.T, fName string) *TestTopoProvider {
	t.Helper()
	topo, err := itopo.LoadFromFile(fName)
	require.NoError(t, err)
	return &TestTopoProvider{Topo: topo.Raw()}
}

// Get returns the stored topology.
func (t *TestTopoProvider) Get() itopo.Topology {
	return itopo.NewTopologyFromRaw(t.Topo)
}
