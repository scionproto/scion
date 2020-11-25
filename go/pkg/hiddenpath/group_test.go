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
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/hiddenpath"
)

func TestNewGroup(t *testing.T) {
	testcases := map[string]struct {
		want  *hiddenpath.Group
		input string
	}{
		"valid json": {
			input: "./testdata/group1.json",
			want: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version: 1,
				Owner:   xtest.MustParseIA("1-ff00:0:110"),
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
		},
		"valid yml": {
			input: "./testdata/group1.yml",
			want: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version: 1,
				Owner:   xtest.MustParseIA("1-ff00:0:110"),
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
		},
	}

	for name, tc := range testcases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := ioutil.ReadFile(tc.input)
			require.NoError(t, err)

			got, err := hiddenpath.ParseGroup(raw)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
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
				Version: 1,
				Owner:   xtest.MustParseIA("1-ff00:0:110"),
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
		"invalid version": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version: 0,
			},
			assertError: assert.Error,
		},
		"invalid owner": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version: 1,
				Owner:   addr.IA{},
			},
			assertError: assert.Error,
		},
		"invalid owner and group id": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version: 1,
				Owner:   xtest.MustParseIA("1-ff00:0:111"),
			},
			assertError: assert.Error,
		},
		"invalid writers": {
			input: &hiddenpath.Group{
				ID: hiddenpath.GroupID{
					OwnerAS: xtest.MustParseAS("ff00:0:110"),
					Suffix:  0x69b5,
				},
				Version:    1,
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
