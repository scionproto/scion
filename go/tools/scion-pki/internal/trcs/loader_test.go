// Copyright 2019 Anapaya Systems
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

package trcs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func TestLoaderLoadConfigs(t *testing.T) {
	tests := map[string]struct {
		Version  scrypto.Version
		Expected scrypto.Version
	}{
		"v1":  {Version: 1, Expected: 1},
		"v2":  {Version: 2, Expected: 2},
		"v3":  {Version: 3, Expected: 3},
		"max": {Version: 0, Expected: 3},
	}

	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l := loader{
				Dirs:    pkicmn.Dirs{Root: "./testdata", Out: "./testdata"},
				Version: test.Version,
			}
			cfgs, err := l.LoadConfigs(testASMap.ISDs())
			require.NoError(t, err)
			assert.Equal(t, test.Expected, cfgs[1].Version)
		})
	}
}
