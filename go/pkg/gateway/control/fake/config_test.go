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

package fake_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/gateway/control"
	"github.com/scionproto/scion/go/pkg/gateway/control/fake"
)

func TestParseConfig(t *testing.T) {
	creationTime := time.Now()
	testCases := map[string]struct {
		file      string
		expected  *fake.Config
		assertErr assert.ErrorAssertionFunc
	}{
		"example file": {
			file: "example_configuration.gatewaytest",
			expected: &fake.Config{
				LocalIA: xtest.MustParseIA("1-ff00:0:110"),
				Chains: []*control.RoutingChain{
					{
						RemoteIA: xtest.MustParseIA("1-ff00:0:112"),
						Prefixes: xtest.MustParseCIDRs(t, "10.0.0.0/24", "10.1.0.0/24"),
						TrafficMatchers: []control.TrafficMatcher{
							{
								ID: 1,
								Matcher: mustParseMatcher(t,
									"ANY(dscp=0x2,ALL(dst=12.12.12.0/26,dscp=0x2,"+
										" NOT(src=12.12.12.0/26)))"),
							},
						},
					},
				},
				Sessions: []*fake.Session{
					{
						ID:         1,
						PolicyID:   1,
						IsUp:       true,
						RemoteAddr: xtest.MustParseUDPAddr(t, "10.0.0.1:30056"),
						RemoteIA:   xtest.MustParseIA("1-ff00:0:112"),
						Paths: []snet.Path{
							snetpath.Path{
								Dst: xtest.MustParseIA("1-ff00:0:112"),
								SPath: spath.Path{
									Raw: []byte{
										0, 0, 32, 0, 1, 0, 10, 217, 96, 87, 95, 109,
										0, 63, 0, 0, 0, 1, 54, 152, 193, 70, 99, 110,
										0, 63, 0, 1, 0, 0, 203, 228, 96, 228, 101, 248},
									Type: scion.PathType,
								},
								NextHop: xtest.MustParseUDPAddr(t, "242.254.100.3:5000"),
								Meta: snet.PathMetadata{
									Interfaces: []snet.PathInterface{
										{
											IA: xtest.MustParseIA("1-ff00:0:110"),
											ID: 1,
										},
										{
											IA: xtest.MustParseIA("1-ff00:0:112"),
											ID: 2,
										},
									},
									MTU:    1280,
									Expiry: creationTime.Add(24 * time.Hour),
								},
							},
						},
					},
				},
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(tc.file)
			require.NoError(t, err)
			defer f.Close()
			c, err := fake.ParseConfig(f, creationTime)
			tc.assertErr(t, err)
			assert.Equal(t, tc.expected, c)
		})
	}
}

func mustParseMatcher(t *testing.T, matcher string) pktcls.Cond {
	t.Helper()
	c, err := pktcls.BuildClassTree(matcher)
	require.NoError(t, err)
	return c
}
