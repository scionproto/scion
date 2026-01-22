// Copyright 2025 ETH Zurich
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

package slices_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slices"
)

func TestModulusIterator(t *testing.T) {
	// Initialize base case.
	s := rangeSlice(0, 10) // 0, 1, ... , 8, 9.
	for i := range s {
		s[i] *= 10 // 0, 10, 20, ... , 80, 90.
	}

	cases := map[string]struct {
		first    int
		count    int
		expected []int
	}{
		"empty": {
			first:    0,
			count:    0,
			expected: []int{},
		},
		"full": {
			first:    0,
			count:    len(s),
			expected: rangeSlice(0, 10),
		},
		"linear": {
			first:    1,
			count:    2,
			expected: []int{1, 2},
		},
		"gap": {
			first:    9,
			count:    1,
			expected: []int{9},
		},
		"discontinuity": {
			first:    9,
			count:    2,
			expected: []int{9, 0},
		},
		"negative_index": {
			first:    -1,
			count:    2,
			expected: []int{9, 0},
		},
		"too_large_index": {
			first:    2*len(s) + 9,
			count:    2,
			expected: []int{9, 0},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := []int{}
			iterator := slices.CircularIterator(s, tc.first, tc.count)
			for i, v := range iterator {
				t.Logf("s[%d] = %v\n", i, v)
				got = append(got, i)
			}
			assert.Equal(t, tc.expected, got)
		})
	}
}

// BenchmarkIterators checks that the performance of the iterators is similar to that of a regular
// for-loop. Deviations of 5% (on both directions, sometimes iterators are faster) are expected.
func BenchmarkIterators(b *testing.B) {
	const benchmarkSliceSize = 1024 * 1024

	b.Run("regular", func(b *testing.B) {
		b.Run("index-value", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				for i, v := range collection {
					sum += v
					_ = i
				}
			}
		})

		b.Run("index", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				for i := range collection {
					sum += collection[i]
				}
			}
		})

		b.Run("value", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				for _, v := range collection {
					sum += v
				}
			}
		})
	})

	b.Run("iterators", func(b *testing.B) {
		b.Run("circular-value", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				iterator := slices.CircularIterator(collection, 1, benchmarkSliceSize)
				for _, v := range iterator {
					sum += v
				}
			}
		})

		b.Run("circular-index", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				iterator := slices.CircularIterator(collection, 1, benchmarkSliceSize)
				for i := range iterator {
					sum += collection[i]
				}
			}
		})

		b.Run("cditerator", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				iterator := slices.CDIterator(collection, 1, benchmarkSliceSize)
				for _, v := range iterator {
					sum += *v
				}
			}
		})

		b.Run("tovalue", func(b *testing.B) {
			collection := make([]int, benchmarkSliceSize)
			sum := 0
			b.ResetTimer()
			for range b.N {
				iterator := slices.ToValueIterator(
					slices.CircularIterator(collection, 1, benchmarkSliceSize))
				for v := range iterator {
					sum += v
				}
			}
		})
	})
}

func rangeSlice(begin, end int) []int {
	s := make([]int, end-begin)
	for i := begin; i < end; i++ {
		s[i] = i
	}
	return s
}
