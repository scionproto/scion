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

package discovery_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/discovery"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

func TestGateways(t *testing.T) {
	testCases := map[string]struct {
		provider    topology.Provider
		want        *dpb.GatewaysResponse
		assertError assert.ErrorAssertionFunc
	}{
		"valid": {
			provider: itopotest.TopoProviderFromFile(t, "testdata/topology.json"),
			want: &dpb.GatewaysResponse{
				Gateways: []*dpb.Gateway{
					{
						ControlAddress:  "127.0.0.82:30100",
						DataAddress:     "127.0.0.82:30101",
						ProbeAddress:    "127.0.0.82:30856",
						AllowInterfaces: []uint64{1, 3, 5},
					},
					{
						ControlAddress: "[2001:db8:f00:b43::1%some-zone]:23425",
						DataAddress:    "[2001:db8:f00:b43::1%some-zone]:30101",
						ProbeAddress:   "[2001:db8:f00:b43::1%some-zone]:30856",
					},
				},
			},
			assertError: assert.NoError,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := discovery.Topology{
				Provider: tc.provider,
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := d.Gateways(ctx, nil)
			tc.assertError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHiddenSegmentServices(t *testing.T) {
	testCases := map[string]struct {
		topo        []byte
		want        *dpb.HiddenSegmentServicesResponse
		assertError assert.ErrorAssertionFunc
	}{
		"no service": {
			topo: []byte(`
			{
				"isd_as": "1-ff00:0:311"
			}
			`),
			want:        &dpb.HiddenSegmentServicesResponse{},
			assertError: assert.NoError,
		},
		"only lookup service": {
			topo: []byte(`
			{
				"isd_as": "1-ff00:0:311",
				"hidden_segment_lookup_service": {
					"hsls-1": {"addr": "10.1.0.1:30254"},
					"hsls-2": {"addr": "10.1.0.2:30254"}
				}
			}
			`),
			want: &dpb.HiddenSegmentServicesResponse{
				Lookup: []*dpb.HiddenSegmentLookupServer{
					{Address: "10.1.0.1:30254"},
					{Address: "10.1.0.2:30254"},
				},
			},
			assertError: assert.NoError,
		},
		"only registration service": {
			topo: []byte(`
			{
				"isd_as": "1-ff00:0:311",
				"hidden_segment_registration_service": {
					"hsls-3": {"addr": "10.1.0.3:30254"},
					"hsls-4": {"addr": "10.1.0.4:30254"}
				}
			}
			`),
			want: &dpb.HiddenSegmentServicesResponse{
				Registration: []*dpb.HiddenSegmentRegistrationServer{
					{Address: "10.1.0.3:30254"},
					{Address: "10.1.0.4:30254"},
				},
			},
			assertError: assert.NoError,
		},
		"both services": {
			topo: []byte(`
			{
				"isd_as": "1-ff00:0:311",
				"hidden_segment_lookup_service": {
					"hsls-1": {"addr": "10.1.0.1:30254"},
					"hsls-2": {"addr": "10.1.0.2:30254"}
				},
				"hidden_segment_registration_service": {
					"hsls-3": {"addr": "10.1.0.3:30254"},
					"hsls-4": {"addr": "10.1.0.4:30254"}
				}
			}
			`),
			want: &dpb.HiddenSegmentServicesResponse{
				Lookup: []*dpb.HiddenSegmentLookupServer{
					{Address: "10.1.0.1:30254"},
					{Address: "10.1.0.2:30254"},
				},
				Registration: []*dpb.HiddenSegmentRegistrationServer{
					{Address: "10.1.0.3:30254"},
					{Address: "10.1.0.4:30254"},
				},
			},
			assertError: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rwTopo, err := topology.RWTopologyFromJSONBytes(tc.topo)
			require.NoError(t, err)
			d := discovery.Topology{Provider: &itopotest.TestTopoProvider{RWTopology: rwTopo}}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			got, err := d.HiddenSegmentServices(ctx, nil)
			tc.assertError(t, err)
			sort.Slice(got.Lookup, func(i, j int) bool {
				return got.Lookup[i].Address < got.Lookup[j].Address
			})
			sort.Slice(got.Registration, func(i, j int) bool {
				return got.Registration[i].Address < got.Registration[j].Address
			})
			assert.Equal(t, tc.want, got)
		})
	}
}
