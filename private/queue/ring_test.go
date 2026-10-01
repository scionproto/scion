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
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/queue/lfring"
)

// newQueue constructs a queue of the given capacity. Both the lock-free ring and
// the naive channel reference provide one. The behavioral tests below run against both.
type newQueue = func(capacity int) queue[int]

// impls lists the implementations the contract test runs against. The channel
// queue is correct by construction. A test that fails on it is a broken test,
// not a broken ring.
var impls = []struct {
	name string
	new  newQueue
}{
	{"ring", func(c int) queue[int] { return lfring.NewRing[int](c) }},
	{"chan", func(c int) queue[int] { return newChanQueue[int](c) }},
}

// TestContract runs the behavioral contract against every implementation.
func TestContract(t *testing.T) {
	for _, im := range impls {
		t.Run(im.name, func(t *testing.T) {
			t.Run("CapRounding", func(t *testing.T) { testCapRounding(t, im.new) })
			t.Run("FIFO", func(t *testing.T) { testFIFO(t, im.new) })
			t.Run("FullAndEmpty", func(t *testing.T) { testFullAndEmpty(t, im.new) })
			t.Run("WrapAround", func(t *testing.T) { testWrapAround(t, im.new) })
			t.Run("Batch", func(t *testing.T) { testBatch(t, im.new) })
			t.Run("ConcurrentMPSC", func(t *testing.T) { testConcurrentMPSC(t, im.new) })
			t.Run("ConcurrentMPMC", func(t *testing.T) { testConcurrentMPMC(t, im.new) })
			t.Run("BatchConcurrent", func(t *testing.T) { testBatchConcurrent(t, im.new) })
		})
	}
}

// testCapRounding tests that Cap rounds the requested size up to a power of two,
// and clamps at both ends.
func testCapRounding(t *testing.T, newQ newQueue) {
	cases := []struct {
		in   int
		want int
	}{
		{-1, 2}, {0, 2}, {1, 2}, {2, 2}, {3, 4}, {4, 4}, {5, 8}, {7, 8}, {8, 8},
		{9, 16}, {1000, 1024}, {1024, 1024}, {1025, 2048},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, newQ(c.in).Cap(), "New(%d).Cap()", c.in)
	}
}

// testFIFO tests that pushed items come back out in the same order.
func testFIFO(t *testing.T, newQ newQueue) {
	q := newQ(8)
	for i := range 8 {
		require.True(t, q.TryPush(i), "TryPush(%d) on a non-full queue", i)
	}
	for i := range 8 {
		v, ok := q.TryPop()
		require.True(t, ok, "TryPop() %d", i)
		require.Equal(t, i, v)
	}
}

// testFullAndEmpty tests that push fails when full, pop fails when empty, and space
// frees after a pop.
func testFullAndEmpty(t *testing.T, newQ newQueue) {
	q := newQ(4) // cap 4
	_, ok := q.TryPop()
	require.False(t, ok, "TryPop on empty queue")
	for i := range 4 {
		require.True(t, q.TryPush(i), "TryPush(%d) before full", i)
	}
	require.False(t, q.TryPush(99), "TryPush on full queue")
	require.Equal(t, 4, q.Len())
	_, ok = q.TryPop()
	require.True(t, ok, "TryPop on full queue")
	require.True(t, q.TryPush(99), "TryPush after a pop")
}

// testWrapAround tests that reusing slots over many laps keeps the order correct.
func testWrapAround(t *testing.T, newQ newQueue) {
	q := newQ(4)
	next := 0
	for lap := range 1000 {
		require.True(t, q.TryPush(next), "push at %d", next)
		v, ok := q.TryPop()
		require.True(t, ok, "lap %d pop", lap)
		require.Equal(t, next, v, "lap %d", lap)
		next++
	}
}

// testBatch tests that [lfring.Ring.PushBatch] and [lfring.Ring.PopBatch] move
// many items at once and stop at full/empty.
func testBatch(t *testing.T, newQ newQueue) {
	q := newQ(8)
	in := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} // 10 into cap-8
	require.Equal(t, 8, q.PushBatch(in), "PushBatch is capped")
	dst := make([]int, 16)
	require.Equal(t, 8, q.PopBatch(dst), "PopBatch")
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7}, dst[:8])
	require.Equal(t, 0, q.PopBatch(dst), "PopBatch on empty")
}

// yieldRetry is called between tries of a full/empty retry loop. Every stress test
// below has to retry, for the reason [lfring]'s package doc gives. Here it is not
// only about speed: with more producers than cores, leaving the yield out turns
// these tests from slow into apparently hung.
func yieldRetry() {
	runtime.Gosched()
}

// stressN scales a per-producer item count down for -short runs, with a floor so
// the test still exercises real concurrency.
func stressN(full int) int {
	n := full
	if testing.Short() {
		n /= 10
	}
	if n < 1000 {
		n = 1000
	}
	return n
}

// firstUnseen returns the index of the first value never marked, or -1 when every
// value was marked. The stress tests track up to a few hundred thousand values.
// One assertion over the scan result keeps that off the assertion path.
func firstUnseen(seen []atomic.Bool) int {
	for v := range seen {
		if !seen[v].Load() {
			return v
		}
	}
	return -1
}

// testConcurrentMPSC tests that no item is lost or duplicated with many writers
// and one reader.
// Build with -race to additionally detect data races.
func testConcurrentMPSC(t *testing.T, newQ newQueue) {
	const producers = 8
	perProd := stressN(50_000)
	total := producers * perProd

	q := newQ(1024)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64

	var wg sync.WaitGroup
	wg.Go(func() {
		for consumed.Load() < int64(total) {
			v, ok := q.TryPop()
			if !ok {
				yieldRetry()
				continue
			}
			assert.False(t, seen[v].Swap(true), "value %d delivered more than once", v)
			consumed.Add(1)
		}
	})
	for p := range producers {
		base := p * perProd
		wg.Go(func() {
			for i := range perProd {
				for !q.TryPush(base + i) {
					yieldRetry()
				}
			}
		})
	}
	wg.Wait()

	require.Equal(t, int64(total), consumed.Load(), "consumed")
	require.Equal(t, -1, firstUnseen(seen), "value never delivered")
}

// testConcurrentMPMC tests that no item is lost or
// duplicated with many writers and many readers.
// Build with -race to additionally detect data races.
func testConcurrentMPMC(t *testing.T, newQ newQueue) {
	const (
		producers = 6
		consumers = 6
	)
	perProd := stressN(40_000)
	total := producers * perProd

	q := newQ(2048)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64

	var wg sync.WaitGroup
	for range consumers {
		wg.Go(func() {
			for consumed.Load() < int64(total) {
				v, ok := q.TryPop()
				if !ok {
					yieldRetry()
					continue
				}
				assert.False(t, seen[v].Swap(true), "value %d consumed twice", v)
				consumed.Add(1)
			}
		})
	}
	for p := range producers {
		base := p * perProd
		wg.Go(func() {
			for i := range perProd {
				for !q.TryPush(base + i) {
					yieldRetry()
				}
			}
		})
	}
	wg.Wait()

	require.Equal(t, int64(total), consumed.Load(), "consumed")
	require.Equal(t, -1, firstUnseen(seen), "value never consumed")
}

// testBatchConcurrent tests that [lfring.Ring.PushBatch] and
// [lfring.Ring.PopBatch] hold the same properties as the concurrent tests.
// Build with -race to additionally detect data races.
func testBatchConcurrent(t *testing.T, newQ newQueue) {
	const producers = 4
	perProd := stressN(60_000)
	total := producers * perProd

	q := newQ(1024)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64

	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]int, 32)
		for consumed.Load() < int64(total) {
			n := q.PopBatch(buf)
			if n == 0 {
				yieldRetry()
				continue
			}
			for _, v := range buf[:n] {
				assert.False(t, seen[v].Swap(true), "value %d consumed twice", v)
			}
			consumed.Add(int64(n))
		}
	})
	for p := range producers {
		base := p * perProd
		wg.Go(func() {
			buf := make([]int, 16)
			i := 0
			for i < perProd {
				n := 0
				for n < len(buf) && i < perProd {
					buf[n] = base + i
					n++
					i++
				}
				for off := 0; off < n; {
					off += q.PushBatch(buf[off:n])
					if off < n {
						yieldRetry()
					}
				}
			}
		})
	}
	wg.Wait()

	require.Equal(t, int64(total), consumed.Load(), "consumed")
	require.Equal(t, -1, firstUnseen(seen), "value never consumed")
}

// --- Benchmarks (concrete types, no interface dispatch). ---

func BenchmarkSinglePushPop(b *testing.B) {
	r := lfring.NewRing[int](1024)
	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		r.TryPush(i)
		r.TryPop()
	}
}

// BenchmarkMPSCRing vs BenchmarkMPSCChan compare the ring against a Go channel
// for the router's producer-many / consumer-one pattern.
func BenchmarkMPSCRing(b *testing.B) {
	r := lfring.NewRing[int](4096)
	benchMPSC(b, 4,
		func(v int) bool { return r.TryPush(v) },
		func() bool { _, ok := r.TryPop(); return ok },
	)
}

func BenchmarkMPSCChan(b *testing.B) {
	q := newChanQueue[int](4096) // the naive reference implementation
	benchMPSC(b, 4,
		q.TryPush,
		func() bool { _, ok := q.TryPop(); return ok },
	)
}

// benchMPSC pushes b.N items across `producers` goroutines while one consumer drains,
// retrying on full/empty, and measures total wall time.
func benchMPSC(b *testing.B, producers int, push func(int) bool, pop func() bool) {
	b.ReportAllocs()
	var consumed atomic.Int64
	target := int64(b.N)
	var wg sync.WaitGroup
	b.ResetTimer()

	wg.Go(func() {
		for consumed.Load() < target {
			if pop() {
				consumed.Add(1)
			} else {
				yieldRetry()
			}
		}
	})
	per := b.N / producers
	rem := b.N % producers
	for p := range producers {
		n := per
		if p < rem {
			n++
		}
		wg.Go(func() {
			for i := range n {
				for !push(i) {
					yieldRetry()
				}
			}
		})
	}
	wg.Wait()
}

// BenchmarkHandoff models the router's actual use: a producer builds a batch
// (the size of the AF_XDP receive batch) and PushBatches it; the consumer
// PopBatches and "processes". Steady-state, continuous flow. P=1 is the
// single-link case (one receiver → one processor queue, effectively SPSC); P=4
// is a multi-link processor queue (MPSC). Ring vs the naive channel reference.
func BenchmarkHandoff(b *testing.B) {
	const batch = 64
	for _, producers := range []int{1, 4} {
		b.Run(fmt.Sprintf("ring/P=%d", producers), func(b *testing.B) {
			r := lfring.NewRing[int](8192)
			benchHandoff(b, producers, batch, r.PushBatch, r.PopBatch)
		})
		b.Run(fmt.Sprintf("chan/P=%d", producers), func(b *testing.B) {
			q := newChanQueue[int](8192)
			benchHandoff(b, producers, batch, q.PushBatch, q.PopBatch)
		})
	}
}

// benchHandoff drives exactly b.N items through push/pop in batches of `batch`,
// across `producers` producer goroutines and one consumer, at steady state.
func benchHandoff(
	b *testing.B,
	producers, batch int,
	push, pop func([]int) int,
) {
	b.ReportAllocs()
	var claimed atomic.Int64  // work handed out to producers
	var consumed atomic.Int64 // items drained by the consumer
	target := int64(b.N)
	var wg sync.WaitGroup
	b.ResetTimer()

	wg.Go(func() {
		dst := make([]int, batch)
		for consumed.Load() < target {
			n := pop(dst)
			if n == 0 {
				yieldRetry()
				continue
			}
			consumed.Add(int64(n))
		}
	})
	for range producers {
		wg.Go(func() {
			buf := make([]int, batch)
			for i := range buf {
				buf[i] = i
			}
			for {
				start := claimed.Add(int64(batch)) - int64(batch)
				if start >= target {
					return
				}
				n := batch
				if start+int64(n) > target {
					n = int(target - start)
				}
				for off := 0; off < n; {
					off += push(buf[off:n])
					if off < n {
						yieldRetry()
					}
				}
			}
		})
	}
	wg.Wait()
}
