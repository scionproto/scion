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

package integration_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/tools/integration"
)

func TestLoadASList(t *testing.T) {
	tests := map[string]struct {
		File     string
		Error    assert.ErrorAssertionFunc
		Expected *integration.ASList
	}{
		"non-existing file": {
			File:  "doesntexist.yml",
			Error: assert.Error,
		},
		"invalid file": {
			File:  "testdata/aslist_invalid.yml",
			Error: assert.Error,
		},
		"valid file": {
			File:  "testdata/aslist_valid.yml",
			Error: assert.NoError,
			Expected: &integration.ASList{
				Core: []addr.IA{addr.MustParseIA("1-ff00:0:110")},
				NonCore: []addr.IA{
					addr.MustParseIA("1-ff00:0:111"),
					addr.MustParseIA("1-ff00:0:112"),
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			asList, err := integration.LoadASList(test.File)
			test.Error(t, err)
			assert.Equal(t, test.Expected, asList)
		})
	}
}
