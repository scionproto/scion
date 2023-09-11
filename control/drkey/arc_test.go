// Copyright 2022 ETH Zurich
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

package drkey_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cs_drkey "github.com/scionproto/scion/control/drkey"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
)

var _ cs_drkey.Level1PrefetchListKeeper = (*cs_drkey.Level1ARC)(nil)

func TestNewLevel1ARC(t *testing.T) {
	_, err := cs_drkey.NewLevel1ARC(-10)
	assert.Error(t, err)
	cache, err := cs_drkey.NewLevel1ARC(5)
	assert.NoError(t, err)
	assert.Len(t, cache.Info(), 0)
}

func TestLevel1ARC(t *testing.T) {
	testCases := map[string]struct {
		size        int
		lengthASes  int
		expected    []cs_drkey.Level1PrefetchInfo
		findInfo    *cs_drkey.Level1PrefetchInfo
		notFindInfo *cs_drkey.Level1PrefetchInfo
	}{
		"single as": {
			size:       5,
			lengthASes: 1,
			expected: []cs_drkey.Level1PrefetchInfo{
				{
					IA:    addr.MustIAFrom(1, 0),
					Proto: drkey.Protocol(0),
				},
			},
		},
		"ten ases": {
			size:       5,
			lengthASes: 10,
			expected: []cs_drkey.Level1PrefetchInfo{
				{
					IA:    addr.MustIAFrom(1, 5),
					Proto: drkey.Protocol(0),
				},
				{
					IA:    addr.MustIAFrom(1, 6),
					Proto: drkey.Protocol(0),
				},
				{
					IA:    addr.MustIAFrom(1, 7),
					Proto: drkey.Protocol(0),
				},
				{
					IA:    addr.MustIAFrom(1, 8),
					Proto: drkey.Protocol(0),
				},
				{
					IA:    addr.MustIAFrom(1, 9),
					Proto: drkey.Protocol(0),
				},
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cache, err := cs_drkey.NewLevel1ARC(tc.size)
			require.NoError(t, err)

			for j := 0; j < 2; j++ {
				for i := 0; i < tc.lengthASes; i++ {
					cacheKey := cs_drkey.Level1PrefetchInfo{
						IA:    addr.MustIAFrom(1, addr.AS(i)),
						Proto: drkey.Protocol(0),
					}
					cache.Update(cacheKey)
				}
			}
			assert.Equal(t, tc.expected, cache.Info())
		})
	}
}
