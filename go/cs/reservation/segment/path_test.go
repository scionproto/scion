// Copyright 2020 ETH Zurich, Anapaya Systems
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

package segment_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segmenttest"
)

func TestValidatePath(t *testing.T) {
	tc := map[string]struct {
		Path    segment.Path
		IsValid bool
	}{
		"src-dst": {
			Path:    segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			IsValid: true,
		},
		"invalid dst": {
			Path:    segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 2),
			IsValid: false,
		},
		"invalid src": {
			Path:    segmenttest.NewPathFromComponents(2, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			IsValid: false,
		},
	}
	for name, tc := range tc {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.Path.Validate()
			if tc.IsValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestEqualPath(t *testing.T) {
	tc := map[string]struct {
		Path1   segment.Path
		Path2   segment.Path
		IsEqual bool
	}{
		"eq1": {
			Path1:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			Path2:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			IsEqual: true,
		},
		"eq2": {
			Path1: segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 2, "ff00:1:10", 3,
				1, "ff00:0:2", 0),
			Path2: segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 2, "ff00:1:10", 3,
				1, "ff00:0:2", 0),
			IsEqual: true,
		},
		"neq1": {
			Path1:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			Path2:   segmenttest.NewPathFromComponents(1, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			IsEqual: false,
		},
		"neq2": {
			Path1:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			Path2:   segmenttest.NewPathFromComponents(0, "ff00:0:3", 1, 1, "ff00:0:2", 0),
			IsEqual: false,
		},
		"neq3": {
			Path1:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 1, "ff00:0:2", 0),
			Path2:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 2, 1, "ff00:0:2", 0),
			IsEqual: false,
		},
		"neq4": {
			Path1: segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 2, "ff00:1:10", 3,
				1, "ff00:0:2", 0),
			Path2:   segmenttest.NewPathFromComponents(0, "ff00:0:1", 1, 2, "ff00:1:10", 3),
			IsEqual: false,
		},
	}
	for name, tc := range tc {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eq := tc.Path1.Equal(tc.Path2)
			require.Equal(t, tc.IsEqual, eq)
		})
	}
}
