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

package slices

import (
	"iter"
)

type Iter[T any] iter.Seq2[int, T]

func CircularTransformingIterator[IN, OUT any](
	s []IN,
	first int,
	count int,
	transform func(index int) OUT,
) Iter[OUT] {
	// XXX(juagargi): beware of the uint casts. They are necessary for the mod operation (down in
	// the for loop) to be efficient. See also the benchmarks' results.
	L := uint(len(s))
	if first < 0 {
		m := (-first)/int(L) + 1
		first += m * int(L)
	} else {
		first = first % int(L)
	}
	return func(yield func(int, OUT) bool) {
		first := uint(first)
		count := uint(count)
		for i := uint(0); i < count; i++ {
			idx := (i + first) % L
			if !yield(int(idx), transform(int(idx))) {
				return
			}
		}
	}
}

// CircularIterator creates a push iterator for the slice that starts at `first` and ends after
// `count` elements. This iterator can be directly used in for-range loops.
func CircularIterator[T any](s []T, first int, count int) Iter[T] {
	return CircularTransformingIterator(s, first, count, func(index int) T {
		return s[index]
	})
}

// CDIterator returns a Circular Dereferencing Iterator, similarly to CircularIterator,
// but each element is the pointer to the original element in the slice.
func CDIterator[T any](s []T, first int, count int) Iter[*T] {
	return CircularTransformingIterator(s, first, count, func(index int) *T {
		return &s[index]
	})
}

// ToValueIterator adapts a index-value push iterator to a value push iterator.
func ToValueIterator[T any](it Iter[T]) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, v := range it {
			if !yield(v) {
				return
			}
		}
	}
}
