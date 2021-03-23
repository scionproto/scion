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

package path_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/xtest"
	apppath "github.com/scionproto/scion/go/pkg/app/path"
)

func TestFilter(t *testing.T) {
	testCases := map[string]struct {
		input, want []snet.Path
		sequence    string
		asserFunc   assert.ErrorAssertionFunc
	}{
		"valid": {
			input: []snet.Path{
				path.Path{
					Dst: xtest.MustParseIA("1-ff00:0:112"),
					Meta: snet.PathMetadata{
						Interfaces: []snet.PathInterface{{ID: 1}},
					},
				},
			},
			sequence:  "0-0#53",
			want:      []snet.Path{},
			asserFunc: assert.NoError,
		},
		"invalid": {
			sequence:  "dummy",
			asserFunc: assert.Error,
		},
	}

	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := apppath.Filter(tc.sequence, tc.input)
			tc.asserFunc(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}

}
