// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package discovery_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/infra/modules/itopo/itopotest"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/discovery"
	dpb "github.com/scionproto/scion/go/pkg/proto/discovery"
)

func TestGateways(t *testing.T) {
	testCases := map[string]struct {
		provider   topology.Provider
		want       *dpb.GatewaysResponse
		asserError assert.ErrorAssertionFunc
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
			asserError: assert.NoError,
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
			tc.asserError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
