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

package hiddenpath_test

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
)

func TestRegistrationPolicyUnmarshalYAML(t *testing.T) {
	testCases := map[string]struct {
		input     string
		want      hiddenpath.RegistrationPolicy
		assertErr assert.ErrorAssertionFunc
	}{
		"valid": {
			input: "testdata/registrationpolicy.yml",
			want: hiddenpath.RegistrationPolicy{
				2: {
					Public: true,
					Groups: map[hiddenpath.GroupID]*hiddenpath.Group{
						mustParseGroupID(t, "ff00:0:110-69b5"): {
							ID:    mustParseGroupID(t, "ff00:0:110-69b5"),
							Owner: xtest.MustParseIA("1-ff00:0:110"),
							Writers: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:111"): {},
								xtest.MustParseIA("1-ff00:0:112"): {},
							},
							Readers: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:114"): {},
							},
							Registries: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:111"): {},
								xtest.MustParseIA("1-ff00:0:113"): {},
							},
						},
						mustParseGroupID(t, "ff00:0:222-abcd"): {
							ID:    mustParseGroupID(t, "ff00:0:222-abcd"),
							Owner: xtest.MustParseIA("1-ff00:0:222"),
							Writers: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:111"): {},
								xtest.MustParseIA("1-ff00:0:112"): {},
							},
							Readers: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:114"): {},
							},
							Registries: map[addr.IA]struct{}{
								xtest.MustParseIA("1-ff00:0:115"): {},
							},
						},
					},
				},
				3: {
					Public: true,
					Groups: make(map[hiddenpath.GroupID]*hiddenpath.Group),
				},
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if *update {
				raw, err := yaml.Marshal(tc.want)
				require.NoError(t, err)
				err = ioutil.WriteFile(tc.input, raw, 0666)
				require.NoError(t, err)
				return
			}
			raw, err := ioutil.ReadFile(tc.input)
			require.NoError(t, err)
			got := make(hiddenpath.RegistrationPolicy)
			err = yaml.Unmarshal(raw, &got)
			tc.assertErr(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mustParseGroupID(t *testing.T, s string) hiddenpath.GroupID {
	t.Helper()

	id, err := hiddenpath.ParseGroupID(s)
	require.NoError(t, err)
	return id
}
