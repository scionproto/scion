// Copyright 2026 SCION Association
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
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/topology"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/router/control"
)

// baseTopology has an interface owned by br1, the router under test,
// and one owned by its sibling br2.
const baseTopology = `{
  "isd_as": "1-ff00:0:110",
  "mtu": 1472,
  "border_routers": {
    "br1": {
      "internal_addr": "127.0.0.1:30001",
      "interfaces": {
        "1": {
          "underlay": {"local": "127.0.0.1:50001", "remote": "127.0.0.2:50001"},
          "isd_as": "1-ff00:0:111",
          "link_to": "child",
          "mtu": 1472
        }
      }
    },
    "br2": {
      "internal_addr": "127.0.0.1:30002",
      "interfaces": {
        "2": {
          "underlay": {"local": "127.0.0.1:50002", "remote": "127.0.0.2:50002"},
          "isd_as": "1-ff00:0:112",
          "link_to": "child",
          "mtu": 1472
        }
      }
    }
  },
  "control_service": {
    "cs1": {"addr": "127.0.0.1:31000"}
  }
}`

// recorder is a Dataplane that records the changes to interfaces and services.
type recorder struct {
	calls []string
	fail  map[string]bool
}

func (r *recorder) record(call string) error {
	r.calls = append(r.calls, call)
	if r.fail[call] {
		return errors.New("failed")
	}
	return nil
}

func (r *recorder) CreateIACtx(ia addr.IA) error {
	return nil
}

func (r *recorder) AddInternalInterface(
	ia addr.IA, localHost addr.Host, provider, local string) error {

	return nil
}

func (r *recorder) AddExternalInterface(ifID iface.ID, info control.LinkInfo,
	localHost, remoteHost addr.Host, owned bool) error {

	return r.record(fmt.Sprintf("add %d %s owned=%t", ifID, info.Remote.Addr, owned))
}

func (r *recorder) DelExternalInterface(ifID iface.ID) error {
	return r.record(fmt.Sprintf("del %d", ifID))
}

func (r *recorder) AddSvc(ia addr.IA, svc addr.SVC, a addr.Host, port uint16) error {
	return r.record(fmt.Sprintf("add %s %s:%d", svc.BaseString(), a, port))
}

func (r *recorder) DelSvc(ia addr.IA, svc addr.SVC, a addr.Host, port uint16) error {
	return r.record(fmt.Sprintf("del %s %s:%d", svc.BaseString(), a, port))
}

func (r *recorder) SetKey(ia addr.IA, index int, key []byte) error {
	return nil
}

func (r *recorder) SetPortRange(start, end uint16) {}

// topo returns baseTopology after edit.
func topo(t *testing.T, edit func(*jsontopo.Topology)) topology.Topology {
	t.Helper()
	var raw jsontopo.Topology
	require.NoError(t, json.Unmarshal([]byte(baseTopology), &raw))
	if edit != nil {
		edit(&raw)
	}
	rw, err := topology.RWTopologyFromJSONTopology(&raw)
	require.NoError(t, err)
	return topology.FromRWTopology(rw)
}

func newInterface(remote string) *jsontopo.BRInterface {
	return &jsontopo.BRInterface{
		Underlay: jsontopo.Underlay{Local: "127.0.0.1:50009", Remote: remote},
		IA:       "1-ff00:0:119",
		LinkTo:   "child",
		MTU:      1472,
	}
}

// configured returns an IACtx for br1 in baseTopology, configured with dp.
func configured(t *testing.T, dp *recorder) *control.IACtx {
	t.Helper()
	cfg, err := control.NewConfig("br1", topo(t, nil), "testdata")
	require.NoError(t, err)
	iac := &control.IACtx{Config: cfg, DP: dp}
	require.NoError(t, iac.Configure())
	dp.calls = nil
	return iac
}

func TestUpdateTopology(t *testing.T) {
	tests := map[string]struct {
		edit  func(*jsontopo.Topology)
		calls []string
	}{
		"unchanged": {},
		"interface added": {
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br1"].Interfaces[3] = newInterface("127.0.0.2:50003")
			},
			calls: []string{"add 3 127.0.0.2:50003 owned=true"},
		},
		"interface removed": {
			edit: func(raw *jsontopo.Topology) {
				delete(raw.BorderRouters["br1"].Interfaces, 1)
			},
			calls: []string{"del 1"},
		},
		"neighbor address changed": {
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br1"].Interfaces[1].Underlay.Remote = "127.0.0.3:50001"
			},
			calls: []string{"del 1", "add 1 127.0.0.3:50001 owned=true"},
		},
		"BFD changed": {
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br1"].Interfaces[1].BFD = &jsontopo.BFD{
					Disable: new(true),
				}
			},
			calls: []string{"del 1", "add 1 127.0.0.2:50001 owned=true"},
		},
		"sibling interface added": {
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br2"].Interfaces[4] = newInterface("127.0.0.2:50004")
			},
			calls: []string{"add 4 127.0.0.1:30002 owned=false"},
		},
		"sibling neighbor address changed": {
			// Only the sibling talks to the neighbor.
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br2"].Interfaces[2].Underlay.Remote = "127.0.0.3:50002"
			},
		},
		"interface moved to sibling": {
			edit: func(raw *jsontopo.Topology) {
				raw.BorderRouters["br2"].Interfaces[1] =
					raw.BorderRouters["br1"].Interfaces[1]
				delete(raw.BorderRouters["br1"].Interfaces, 1)
			},
			calls: []string{"del 1", "add 1 127.0.0.1:30002 owned=false"},
		},
		"control service moved": {
			edit: func(raw *jsontopo.Topology) {
				raw.ControlService["cs1"].Addr = "127.0.0.1:31001"
			},
			calls: []string{"add CS 127.0.0.1:31001", "del CS 127.0.0.1:31000"},
		},
		"discovery service added": {
			edit: func(raw *jsontopo.Topology) {
				raw.DiscoveryService = map[string]*jsontopo.ServerInfo{
					"ds1": {Addr: "127.0.0.1:31002"},
				}
			},
			calls: []string{"add DS 127.0.0.1:31002"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dp := &recorder{}
			iac := configured(t, dp)
			require.NoError(t, iac.UpdateTopology(topo(t, tc.edit)))
			assert.Equal(t, tc.calls, dp.calls)
		})
	}
}

func TestUpdateTopologyRetries(t *testing.T) {
	dp := &recorder{}
	iac := configured(t, dp)
	changed := topo(t, func(raw *jsontopo.Topology) {
		raw.BorderRouters["br1"].Interfaces[1].Underlay.Remote = "127.0.0.3:50001"
		raw.BorderRouters["br1"].Interfaces[3] = newInterface("127.0.0.2:50003")
	})

	// Interface 1 stays as it is, and interface 3 is not added.
	dp.fail = map[string]bool{"del 1": true, "add 3 127.0.0.2:50003 owned=true": true}
	assert.Error(t, iac.UpdateTopology(changed))
	assert.Equal(t, []string{"del 1", "add 3 127.0.0.2:50003 owned=true"}, dp.calls)

	dp.fail = nil
	dp.calls = nil
	require.NoError(t, iac.UpdateTopology(changed))
	assert.Equal(t, []string{
		"del 1",
		"add 1 127.0.0.3:50001 owned=true",
		"add 3 127.0.0.2:50003 owned=true",
	}, dp.calls)
}

func TestUpdateTopologyRejects(t *testing.T) {
	tests := map[string]func(*jsontopo.Topology){
		"ISD-AS changed": func(raw *jsontopo.Topology) {
			raw.IA = "1-ff00:0:120"
		},
		"internal address changed": func(raw *jsontopo.Topology) {
			raw.BorderRouters["br1"].InternalAddr = "127.0.0.1:30009"
		},
		"router removed": func(raw *jsontopo.Topology) {
			delete(raw.BorderRouters, "br1")
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			dp := &recorder{}
			iac := configured(t, dp)
			assert.Error(t, iac.UpdateTopology(topo(t, edit)))
			assert.Empty(t, dp.calls)
		})
	}
}
