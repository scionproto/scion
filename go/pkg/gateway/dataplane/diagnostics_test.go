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

package dataplane_test

import (
	"bytes"
	"flag"
	"io/ioutil"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/dataplane"
)

var (
	update = flag.Bool("update", false, "update the golden files of this test")
)

func TestDiagnosticWriter(t *testing.T) {
	testCases := map[string]struct {
		prepareDW func(t *testing.T) dataplane.DiagnosticsWriter
		wantFile  string
	}{
		"routingtable": {
			prepareDW: func(t *testing.T) dataplane.DiagnosticsWriter {
				dp := dataplane.NewRoutingTable(nil, []*control.RoutingChain{
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.0.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 1, Matcher: pktcls.NewCondAllOf()},
						},
					},
					{
						Prefixes: []*net.IPNet{xtest.MustParseCIDR(t, "192.168.100.0/24")},
						TrafficMatchers: []control.TrafficMatcher{
							{ID: 2, Matcher: pktcls.NewCondAllOf()},
							{ID: 3, Matcher: pktcls.NewCondNot(nil)},
						},
					},
				})
				dp.AddRoute(1, testPktWriter{ID: 1})
				dp.AddRoute(2, testPktWriter{ID: 2})
				return dp
			},
			wantFile: "./testdata/routingtable1.txt",
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			tc.prepareDW(t).DiagnosticsWrite(&buf)
			if *update {
				err := ioutil.WriteFile(tc.wantFile, buf.Bytes(), 0644)
				require.NoError(t, err)
				return
			}

			want, err := ioutil.ReadFile(tc.wantFile)
			require.NoError(t, err)
			assert.Equal(t, string(want), buf.String())
		})
	}
}
