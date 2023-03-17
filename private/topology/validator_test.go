// Copyright 2021 Anapaya Systems
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

package topology_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/private/topology"
)

func TestDefaultValidatorValidate(t *testing.T) {
	testCases := map[string]struct {
		loadOld   func(*testing.T) *topology.RWTopology
		loadNew   func(*testing.T) *topology.RWTopology
		assertErr assert.ErrorAssertionFunc
	}{
		"new nil is invalid": {
			loadOld:   noTopo,
			loadNew:   noTopo,
			assertErr: assert.Error,
		},
		"new topology ok": {
			loadOld:   noTopo,
			loadNew:   defaultTopo,
			assertErr: assert.NoError,
		},
		"ia immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIA(0)),
			assertErr: assert.Error,
		},
		"mtu immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setMTU(42)),
			assertErr: assert.Error,
		},
		"attributes immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIsCore(true)),
			assertErr: assert.Error,
		},
		"valid update": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				topo.Timestamp = time.Now()
			}),
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := topology.DefaultValidator{}
			old := tc.loadOld(t)
			new := tc.loadNew(t)
			err := v.Validate(new, old)
			tc.assertErr(t, err)
		})
	}
}

func TestControlValidatorValidate(t *testing.T) {
	id := "cs1-ff00:0:311-3"
	other := "cs1-ff00:0:311-1"
	testCases := map[string]struct {
		loadOld   func(*testing.T) *topology.RWTopology
		loadNew   func(*testing.T) *topology.RWTopology
		assertErr assert.ErrorAssertionFunc
	}{
		"new nil is invalid": {
			loadOld:   noTopo,
			loadNew:   noTopo,
			assertErr: assert.Error,
		},
		"new topology ok": {
			loadOld:   noTopo,
			loadNew:   defaultTopo,
			assertErr: assert.NoError,
		},
		"service missing": {
			loadOld: noTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				delete(topo.CS, id)
			}),
			assertErr: assert.Error,
		},
		"ia immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIA(0)),
			assertErr: assert.Error,
		},
		"mtu immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setMTU(42)),
			assertErr: assert.Error,
		},
		"attributes immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIsCore(true)),
			assertErr: assert.Error,
		},
		"valid update": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				topo.Timestamp = time.Now()
			}),
			assertErr: assert.NoError,
		},
		"modifying other service is ok": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				svcInfo := topo.CS[other]
				svcInfo.UnderlayAddress = &net.UDPAddr{Port: 42}
				topo.CS[other] = svcInfo
			}),
			assertErr: assert.NoError,
		},
		"modifying own service fails": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				svcInfo := topo.CS[id]
				svcInfo.UnderlayAddress = &net.UDPAddr{Port: 42}
				topo.CS[id] = svcInfo
			}),
			assertErr: assert.Error,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := topology.ControlValidator{ID: id}
			old := tc.loadOld(t)
			new := tc.loadNew(t)
			err := v.Validate(new, old)
			tc.assertErr(t, err)
		})
	}
}

func TestRouterValidatorValidate(t *testing.T) {
	id := "br1-ff00:0:311-1"
	other := "br1-ff00:0:311-2"
	testCases := map[string]struct {
		loadOld   func(*testing.T) *topology.RWTopology
		loadNew   func(*testing.T) *topology.RWTopology
		assertErr assert.ErrorAssertionFunc
	}{
		"new nil is invalid": {
			loadOld:   noTopo,
			loadNew:   noTopo,
			assertErr: assert.Error,
		},
		"new topology ok": {
			loadOld:   noTopo,
			loadNew:   defaultTopo,
			assertErr: assert.NoError,
		},
		"router missing": {
			loadOld: noTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				delete(topo.BR, id)
			}),
			assertErr: assert.Error,
		},
		"ia immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIA(0)),
			assertErr: assert.Error,
		},
		"mtu immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setMTU(42)),
			assertErr: assert.Error,
		},
		"attributes immutable": {
			loadOld:   defaultTopo,
			loadNew:   topoWithModification(t, setIsCore(true)),
			assertErr: assert.Error,
		},
		"valid update": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				topo.Timestamp = time.Now()
			}),
			assertErr: assert.NoError,
		},
		"self immutable": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				topo.BR[id].InternalAddr.Port = 42
			}),
			assertErr: assert.Error,
		},
		"other mutable": {
			loadOld: defaultTopo,
			loadNew: topoWithModification(t, func(topo *topology.RWTopology) {
				topo.BR[other].InternalAddr.Port = 42
			}),
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			v := topology.RouterValidator{ID: id}
			old := tc.loadOld(t)
			new := tc.loadNew(t)
			err := v.Validate(new, old)
			tc.assertErr(t, err)
		})
	}
}

func noTopo(_ *testing.T) *topology.RWTopology { return nil }

func defaultTopo(t *testing.T) *topology.RWTopology {
	return loadTopo(t, "testdata/basic.json")
}

func topoWithModification(
	t *testing.T,
	mod func(topo *topology.RWTopology),
) func(t *testing.T) *topology.RWTopology {

	return func(t *testing.T) *topology.RWTopology {
		topo := defaultTopo(t)
		mod(topo)
		return topo
	}
}
func setIA(ia addr.IA) func(topo *topology.RWTopology) {
	return func(topo *topology.RWTopology) {
		topo.IA = ia
	}
}

func setMTU(mtu int) func(topo *topology.RWTopology) {
	return func(topo *topology.RWTopology) {
		topo.MTU = mtu
	}
}

func setIsCore(isCore bool) func(topo *topology.RWTopology) {
	return func(topo *topology.RWTopology) {
		topo.IsCore = isCore
	}
}

func loadTopo(t *testing.T, filename string) *topology.RWTopology {
	t.Helper()
	topo, err := topology.RWTopologyFromJSONFile(filename)
	require.NoError(t, err)
	return topo
}
