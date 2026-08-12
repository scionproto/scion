// Copyright 2026 SCION Association
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

package queue

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/queue/lfring"
)

// queue is the common interface satisfied by both the lock-free [lfring.Ring]
// and the naive channel reference. Tests and benchmarks run against either.
type queue[T any] interface {
	TryPush(T) bool
	TryPop() (T, bool)
	PushBatch([]T) int
	PopBatch([]T) int
	Cap() int
	Len() int
}

var (
	_ queue[int] = (*lfring.Ring[int])(nil)
	_ queue[int] = (*chanQueue[int])(nil)
)

// chanQueue is a bounded FIFO queue backed by a buffered Go channel. It is the
// reference the lock-free [lfring.Ring] is validated and benchmarked against.
// It rounds capacity the same way, which makes the two directly comparable.
type chanQueue[T any] struct {
	ch  chan T
	cap int
}

func newChanQueue[T any](capacity int) *chanQueue[T] {
	size := int(roundUpPow2(capacity))
	return &chanQueue[T]{ch: make(chan T, size), cap: size}
}

// roundUpPow2 returns the smallest power of two >= v, clamped to [2, lfring.MaxCapacity].
// It is deliberately a second implementation of the rounding [lfring.NewRing] applies,
// rather than a call into it: a reference model that reused the code under test
// could not expose a bug in that rounding.
func roundUpPow2(v int) uint32 {
	if v < 2 {
		return 2
	}
	if v > lfring.MaxCapacity {
		return lfring.MaxCapacity
	}
	n := uint32(2)
	for n < uint32(v) {
		n *= 2
	}
	return n
}

func (q *chanQueue[T]) TryPush(v T) bool {
	select {
	case q.ch <- v:
		return true
	default:
		return false
	}
}

func (q *chanQueue[T]) TryPop() (v T, ok bool) {
	select {
	case v = <-q.ch:
		return v, true
	default:
		return v, false
	}
}

func (q *chanQueue[T]) PushBatch(vs []T) int {
	for i := range vs {
		if !q.TryPush(vs[i]) {
			return i
		}
	}
	return len(vs)
}

func (q *chanQueue[T]) PopBatch(dst []T) int {
	for i := range dst {
		v, ok := q.TryPop()
		if !ok {
			return i
		}
		dst[i] = v
	}
	return len(dst)
}

func (q *chanQueue[T]) Cap() int { return q.cap }
func (q *chanQueue[T]) Len() int { return len(q.ch) }

// TestRingMatchesReference tests that the ring and the simple channel queue return
// the same result at every step of one random op sequence (single-threaded).
func TestRingMatchesReference(t *testing.T) {
	const capacity = 8
	r := lfring.NewRing[int](capacity)
	ref := newChanQueue[int](capacity)
	require.Equal(t, ref.Cap(), r.Cap(), "Cap")

	rng := rand.New(rand.NewSource(1))
	dstR := make([]int, 6)
	dstRef := make([]int, 6)

	for step := range 300_000 {
		switch rng.Intn(4) {
		case 0: // TryPush
			v := rng.Int()
			require.Equal(t, ref.TryPush(v), r.TryPush(v), "step %d TryPush(%d)", step, v)
		case 1: // TryPop
			gv, gok := r.TryPop()
			wv, wok := ref.TryPop()
			require.Equal(t, wok, gok, "step %d TryPop ok", step)
			if wok {
				require.Equal(t, wv, gv, "step %d TryPop value", step)
			}
		case 2: // PushBatch
			n := rng.Intn(len(dstR) + 1)
			vs := make([]int, n)
			for i := range vs {
				vs[i] = rng.Int()
			}
			require.Equal(t, ref.PushBatch(vs), r.PushBatch(vs), "step %d PushBatch(%d)", step, n)
		case 3: // PopBatch
			k := rng.Intn(len(dstR) + 1)
			nR := r.PopBatch(dstR[:k])
			nRef := ref.PopBatch(dstRef[:k])
			require.Equal(t, nRef, nR, "step %d PopBatch(%d)", step, k)
			require.Equal(t, dstRef[:nRef], dstR[:nR], "step %d PopBatch values", step)
		}
		require.Equal(t, ref.Len(), r.Len(), "step %d Len", step)
	}
}

// FuzzRingVsReference tests that the ring and the channel queue stay in lockstep on
// a random op program built from the fuzzer input. Any divergence is a ring bug.
func FuzzRingVsReference(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 1, 1}, uint8(3))
	f.Add([]byte{2, 6, 10, 1, 0, 3}, uint8(7))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, prog []byte, capSel uint8) {
		capacity := int(capSel % 17) // small (0..16) so full/empty edges are hit often
		r := lfring.NewRing[int](capacity)
		ref := newChanQueue[int](capacity)
		require.Equal(t, ref.Cap(), r.Cap(), "Cap")
		counter := 0
		dstR := make([]int, 8)
		dstRef := make([]int, 8)
		for _, b := range prog {
			switch b & 3 {
			case 0: // TryPush
				v := counter
				counter++
				require.Equal(t, ref.TryPush(v), r.TryPush(v), "TryPush(%d)", v)
			case 1: // TryPop
				gv, gok := r.TryPop()
				wv, wok := ref.TryPop()
				require.Equal(t, wok, gok, "TryPop ok")
				if wok {
					require.Equal(t, wv, gv, "TryPop value")
				}
			case 2: // PushBatch
				k := int(b>>2) & 7
				vs := make([]int, k)
				for i := range vs {
					vs[i] = counter
					counter++
				}
				require.Equal(t, ref.PushBatch(vs), r.PushBatch(vs), "PushBatch(%d)", k)
			case 3: // PopBatch
				k := int(b>>2) & 7
				nR := r.PopBatch(dstR[:k])
				nRef := ref.PopBatch(dstRef[:k])
				require.Equal(t, nRef, nR, "PopBatch(%d)", k)
				require.Equal(t, dstRef[:nRef], dstR[:nR], "PopBatch values")
			}
			require.Equal(t, ref.Len(), r.Len(), "Len")
		}
	})
}
