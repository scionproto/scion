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

package control_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

func TestRouteString(t *testing.T) {
	testCases := map[string]struct {
		Route  *control.Route
		String string
	}{
		"nil": {
			Route:  nil,
			String: "<nil>",
		},
		"nil prefix": {
			Route: &control.Route{
				NextHop: net.ParseIP("192.168.0.1"),
			},
			String: "<nil> via 192.168.0.1",
		},
		"only IPv4 prefix": {
			Route: &control.Route{
				Prefix:  xtest.MustParseCIDR(t, "192.168.0.0/24"),
				NextHop: net.ParseIP("192.168.0.1"),
			},
			String: "192.168.0.0/24 via 192.168.0.1",
		},
		"only IPv6 prefix": {
			Route: &control.Route{
				Prefix:  xtest.MustParseCIDR(t, "2001:db8::/32"),
				NextHop: net.ParseIP("2001:db8::1"),
			},
			String: "2001:db8::/32 via 2001:db8::1",
		},
		"nil next hop": {
			Route: &control.Route{
				Prefix: xtest.MustParseCIDR(t, "192.168.0.0/24"),
			},
			String: "192.168.0.0/24 via <nil>",
		},
		"IPv4 with source": {
			Route: &control.Route{
				Prefix:  xtest.MustParseCIDR(t, "192.168.0.0/24"),
				NextHop: net.ParseIP("192.168.0.1"),
				Source:  net.ParseIP("192.168.0.2"),
			},
			String: "192.168.0.0/24 via 192.168.0.1 src 192.168.0.2",
		},
		"IPv4 with source and IA": {
			Route: &control.Route{
				Prefix:  xtest.MustParseCIDR(t, "192.168.0.0/24"),
				NextHop: net.ParseIP("192.168.0.1"),
				Source:  net.ParseIP("192.168.0.2"),
				IA:      xtest.MustParseIA("1-ff00:0:1"),
			},
			String: "192.168.0.0/24 via 192.168.0.1 src 192.168.0.2 isd-as 1-ff00:0:1",
		},
		"IPv4 with IA": {
			Route: &control.Route{
				Prefix:  xtest.MustParseCIDR(t, "192.168.0.0/24"),
				NextHop: net.ParseIP("192.168.0.1"),
				IA:      xtest.MustParseIA("1-ff00:0:1"),
			},
			String: "192.168.0.0/24 via 192.168.0.1 isd-as 1-ff00:0:1",
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.String, tc.Route.String())
		})
	}
}
