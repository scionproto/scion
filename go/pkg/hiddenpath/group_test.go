// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"flag"
	"io/ioutil"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
)

var update = flag.Bool("update", false, "Update the golden files for this test.")

func TestGroupIDUint64Conversion(t *testing.T) {
	testCases := []hiddenpath.GroupID{
		{OwnerAS: xtest.MustParseAS("ff00:0:110"), Suffix: 24},
		{OwnerAS: xtest.MustParseAS("ff00:0:112"), Suffix: 0},
	}
	for i, id := range testCases {
		i, id := i, id
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			raw := id.ToUint64()
			assert.Equal(t, id, hiddenpath.GroupIDFromUint64(raw))
		})
	}
}

func TestNewGroup(t *testing.T) {
	testcases := map[string]struct {
		want  hiddenpath.Groups
		input string
	}{
		"valid": {
			input: "./testdata/groups.yml",
			want: hiddenpath.Groups{
				hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				}: {
					ID: hiddenpath.GroupID{
						OwnerAS: xtest.MustParseAS("ff00:0:110"),
						Suffix:  0x69b5,
					},
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
				hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:222"),
					Suffix:  0xabcd,
				}: {
					ID: hiddenpath.GroupID{
						OwnerAS: xtest.MustParseAS("ff00:0:222"),
						Suffix:  0xabcd,
					},
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
	}

	for name, tc := range testcases {
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

			got, err := hiddenpath.LoadHiddenPathGroups(tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGroupValidate(t *testing.T) {
	testcases := map[string]struct {
		input       *hiddenpath.Group
		assertError assert.ErrorAssertionFunc
	}{
		"valid": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Owner: xtest.MustParseIA("1-ff00:0:110"),
				Writers: map[addr.IA]struct{}{
					xtest.MustParseIA("1-ff00:0:111"): {},
					xtest.MustParseIA("1-ff00:0:112"): {},
				},
				Readers: map[addr.IA]struct{}{
					xtest.MustParseIA("1-ff00:0:113"): {},
					xtest.MustParseIA("1-ff00:0:114"): {},
				},
				Registries: map[addr.IA]struct{}{
					xtest.MustParseIA("1-ff00:0:110"): {},
					xtest.MustParseIA("1-ff00:0:111"): {},
					xtest.MustParseIA("1-ff00:0:115"): {},
				},
			},
			assertError: assert.NoError,
		},
		"invalid group id": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{},
			},
			assertError: assert.Error,
		},
		"invalid owner": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Owner: addr.IA{},
			},
			assertError: assert.Error,
		},
		"invalid owner and group id": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Owner: xtest.MustParseIA("1-ff00:0:111"),
			},
			assertError: assert.Error,
		},
		"invalid writers": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Owner:      xtest.MustParseIA("1-ff00:0:110"),
				Writers:    map[addr.IA]struct{}{},
				Readers:    map[addr.IA]struct{}{},
				Registries: map[addr.IA]struct{}{},
			},
			assertError: assert.Error,
		},
	}

	for name, tc := range testcases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tc.input.Validate()
			tc.assertError(t, err)
		})
	}
}
