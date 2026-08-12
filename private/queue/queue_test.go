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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/private/queue/chanq"
	"github.com/scionproto/scion/private/queue/lfring"
)

var (
	_ Queue[int] = (*chanq.Queue[int])(nil)
	_ Queue[int] = (*lfring.Queue[int])(nil)
)

// newBlockingQueue constructs a [Queue] of at least the given capacity.
type newBlockingQueue = func(capacity int) Queue[int]

// queueImpls lists the [Queue] implementations the contract test runs against.
var queueImpls = []struct {
	name string
	new  newBlockingQueue
}{
	{"chan", func(c int) Queue[int] { return chanq.New[int](c) }},
	{"ring", func(c int) Queue[int] { return lfring.New[int](c) }},
}

// TestQueueImpl runs the [Queue] contract against every implementation.
func TestQueueImpl(t *testing.T) {
	for _, im := range queueImpls {
		t.Run(im.name, func(t *testing.T) {
			t.Run("FIFO", func(t *testing.T) {
				testQueueFIFO(t, im.new)
			})
			t.Run("Len", func(t *testing.T) {
				testQueueLen(t, im.new)
			})
			t.Run("Full", func(t *testing.T) {
				testQueueFull(t, im.new)
			})
			t.Run("EnqueueBlocking", func(t *testing.T) {
				testQueueEnqueueBlocking(t, im.new)
			})
			t.Run("EnqueueBlockingWakes", func(t *testing.T) {
				testQueueEnqueueBlockingWakes(t, im.new)
			})
			t.Run("TryDequeueEmpty", func(t *testing.T) {
				testQueueTryEmpty(t, im.new)
			})
			t.Run("BlockThenWake", func(t *testing.T) {
				testQueueBlockThenWake(t, im.new)
			})
			t.Run("CloseWakes", func(t *testing.T) {
				testQueueCloseWakes(t, im.new)
			})
			t.Run("CloseDrains", func(t *testing.T) {
				testQueueCloseDrains(t, im.new)
			})
			t.Run("CloseDrainsTry", func(t *testing.T) {
				testQueueCloseDrainsTry(t, im.new)
			})
			t.Run("ParkHandshake", func(t *testing.T) {
				testQueueParkHandshake(t, im.new)
			})
			t.Run("ConcurrentMPSC", func(t *testing.T) {
				testQueueMPSC(t, im.new)
			})
		})
	}
}

// testQueueFIFO tests that values come back out in enqueue order.
func testQueueFIFO(t *testing.T, newQ newBlockingQueue) {
	q := newQ(8)
	n := q.Cap()
	for i := range n {
		require.True(t, q.Enqueue(i), "Enqueue(%d) below capacity", i)
	}
	for i := range n {
		v, ok := q.Dequeue() // items are present, this does not block
		require.True(t, ok, "Dequeue() %d", i)
		require.Equal(t, i, v)
	}
}

// testQueueLen tests that Len reports the number of queued values.
func testQueueLen(t *testing.T, newQ newBlockingQueue) {
	q := newQ(8)
	require.Equal(t, 0, q.Len(), "empty queue")
	q.Enqueue(1)
	q.Enqueue(2)
	q.Enqueue(3)
	require.Equal(t, 3, q.Len())
}

// testQueueEnqueueBlocking tests that [Writer.EnqueueBlocking] waits while full
// and completes once a dequeue frees a slot.
func testQueueEnqueueBlocking(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	n := q.Cap()
	for i := range n {
		require.True(t, q.Enqueue(i), "Enqueue(%d) before full", i)
	}
	done := make(chan struct{})
	go func() {
		q.EnqueueBlocking(999)
		close(done)
	}()
	// Full queue: the blocking enqueue must not complete yet.
	select {
	case <-done:
		require.Fail(t, "EnqueueBlocking returned while the queue was full")
	case <-time.After(20 * time.Millisecond):
	}
	// Free a slot. The blocking enqueue now completes.
	_, ok := q.Dequeue()
	require.True(t, ok, "Dequeue")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.Fail(t, "EnqueueBlocking did not complete after a slot freed")
	}
	require.Equal(t, n, q.Len(), "after refill")
}

// testQueueEnqueueBlockingWakes tests that [Writer.EnqueueBlocking] on a non-full
// queue wakes a consumer parked in [Reader.Dequeue].
func testQueueEnqueueBlockingWakes(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	res := make(chan int, 1)
	go func() {
		if v, ok := q.Dequeue(); ok {
			res <- v
		}
	}()
	time.Sleep(20 * time.Millisecond) // let the consumer park
	q.EnqueueBlocking(7)              // Room available. This pushes and must wake it.
	select {
	case v := <-res:
		require.Equal(t, 7, v, "Dequeue woke with the wrong value")
	case <-time.After(2 * time.Second):
		require.Fail(t, "EnqueueBlocking did not wake a parked consumer")
	}
}

// testQueueFull tests that [Writer.Enqueue] fails when full and space frees after
// a dequeue.
func testQueueFull(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	n := q.Cap()
	for i := range n {
		require.True(t, q.Enqueue(i), "Enqueue(%d) before full (cap %d)", i, n)
	}
	require.False(t, q.Enqueue(999), "Enqueue on full queue")
	_, ok := q.TryDequeue()
	require.True(t, ok, "TryDequeue on full queue")
	require.True(t, q.Enqueue(999), "Enqueue after a dequeue")
}

// testQueueTryEmpty tests that [Reader.TryDequeue] on an empty queue reports
// not-ok and does not block.
func testQueueTryEmpty(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	_, ok := q.TryDequeue()
	require.False(t, ok, "TryDequeue on empty queue")
}

// testQueueBlockThenWake tests that a consumer blocked on an empty queue wakes and
// returns the value once a producer enqueues. Exercises the ring's park/wake path.
func testQueueBlockThenWake(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	res := make(chan int, 1)
	go func() {
		if v, ok := q.Dequeue(); ok {
			res <- v
		}
	}()
	time.Sleep(20 * time.Millisecond) // bias toward the consumer actually parking
	require.True(t, q.Enqueue(42), "Enqueue")
	select {
	case v := <-res:
		require.Equal(t, 42, v, "Dequeue woke with the wrong value")
	case <-time.After(2 * time.Second):
		require.Fail(t, "Dequeue did not wake after Enqueue")
	}
}

// testQueueCloseWakes tests that Close unblocks a consumer parked on an empty queue
// and that [Reader.Dequeue] reports not-ok (the stop signal).
func testQueueCloseWakes(t *testing.T, newQ newBlockingQueue) {
	q := newQ(4)
	res := make(chan bool, 1)
	go func() {
		_, ok := q.Dequeue()
		res <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	q.Close()
	select {
	case ok := <-res:
		require.False(t, ok, "Dequeue after Close on an empty queue")
	case <-time.After(2 * time.Second):
		require.Fail(t, "Close did not wake a parked Dequeue")
	}
}

// testQueueCloseDrains tests that after [Queue.Close], [Reader.Dequeue] still
// returns every buffered value in order, then reports not-ok.
func testQueueCloseDrains(t *testing.T, newQ newBlockingQueue) {
	q := newQ(8)
	n := q.Cap()
	for i := range n {
		require.True(t, q.Enqueue(i), "Enqueue(%d)", i)
	}
	q.Close()
	for i := range n {
		v, ok := q.Dequeue()
		require.True(t, ok, "Dequeue() %d", i)
		require.Equal(t, i, v)
	}
	_, ok := q.Dequeue()
	require.False(t, ok, "Dequeue after draining a closed queue")
}

// testQueueCloseDrainsTry tests that after [Queue.Close], [Reader.TryDequeue] still
// returns every buffered value in order, then reports not-ok. This is the batch-fill
// half of the drain: a consumer that keeps calling TryDequeue on a closed queue must
// be told to stop rather than handed zero values.
func testQueueCloseDrainsTry(t *testing.T, newQ newBlockingQueue) {
	q := newQ(8)
	n := q.Cap()
	for i := range n {
		require.True(t, q.Enqueue(i), "Enqueue(%d)", i)
	}
	q.Close()
	for i := range n {
		v, ok := q.TryDequeue()
		require.True(t, ok, "TryDequeue() %d", i)
		require.Equal(t, i, v)
	}
	_, ok := q.TryDequeue()
	require.False(t, ok, "TryDequeue after draining a closed queue")
}

// burn is a calibrated delay of roughly n nanoseconds. It has to resolve single
// nanoseconds, which rules out both time.Sleep and runtime.Gosched:
// one step of Gosched is over a hundred nanoseconds and steps straight over
// the window testQueueParkHandshake is looking for.
func burn(n int) {
	x := uint64(0)
	for i := range n {
		x += uint64(i) ^ (x >> 3)
	}
	burnSink.Store(x)
}

// burnSink keeps the compiler from discarding burn's loop.
var burnSink atomic.Uint64

// testQueueParkHandshake tests the boundary between a consumer deciding to park and
// a producer deciding to signal.
//
// A consumer that finds the queue empty has to announce that it is about to park
// before it takes its last look, not after. Announce afterwards and this ordering exists:
// consumer looks and finds nothing, producer enqueues and reads the not-yet-set flag so
// it stays silent, consumer announces and parks.
// The value is queued and nobody is coming to say so.
//
// Each round starts one consumer and one producer together and enqueues a single value,
// the only one coming. A wakeup lost there is a hang rather than a delay.
// The window between the consumer's last look and its announcement is a
// couple of instructions, far too narrow to hit by starting the two at the same instant.
// Instead the producer's start is swept in ~1ns steps across the whole path the
// consumer takes to the park, and each offset is retried. Some rounds then land
// inside the window.
//
// Cost is about half a second, and it separates cleanly: the ordering above fails
// this within a couple of hundred thousand rounds while the correct one never does.
func testQueueParkHandshake(t *testing.T, newQ newBlockingQueue) {
	// offsets spans the consumer's path to the park with room to spare on a
	// slower machine. reps retries each offset, since the two goroutines do not
	// land on the same relative timing twice.
	offsets, reps := 512, 400
	if testing.Short() {
		reps = 50
	}
	for offset := range offsets {
		for range reps {
			q := newQ(4)
			got := make(chan int, 1)
			var gate atomic.Bool
			// Both goroutines have to be running already when the gate opens.
			// Waiting on a channel would put one to sleep, and waking it up
			// again takes microseconds. The window this test aims at is a few
			// nanoseconds wide. Spin instead, and do not yield either.
			go func() {
				for !gate.Load() {
				}
				if v, ok := q.Dequeue(); ok {
					got <- v
				}
			}()
			go func() {
				for !gate.Load() {
				}
				burn(offset)
				q.Enqueue(7)
			}()
			gate.Store(true)
			select {
			case v := <-got:
				require.Equal(t, 7, v)
			case <-time.After(2 * time.Second):
				// Two goroutines and one value. Two seconds is not scheduling noise,
				// it is a wakeup that never came.
				require.FailNow(t, "lost wakeup",
					"producer offset %d: consumer never woke, %d value(s) queued",
					offset, q.Len())
			}
			q.Close()
		}
	}
}

// testQueueMPSC tests that no value is lost or duplicated with many producers and
// one consumer (the queue's target use). Build with -race to also check for races.
func testQueueMPSC(t *testing.T, newQ newBlockingQueue) {
	const producers = 6
	perProd := stressN(40_000)
	total := producers * perProd

	q := newQ(1024)
	seen := make([]atomic.Bool, total)
	var consumed atomic.Int64
	done := make(chan struct{})

	go func() {
		for {
			v, ok := q.Dequeue()
			if !ok {
				break
			}
			assert.False(t, seen[v].Swap(true), "value %d delivered more than once", v)
			if consumed.Add(1) == int64(total) {
				break
			}
		}
		close(done)
	}()

	var wg sync.WaitGroup
	for p := range producers {
		base := p * perProd
		wg.Go(func() {
			for i := range perProd {
				for !q.Enqueue(base + i) {
					yieldRetry()
				}
			}
		})
	}
	wg.Wait()
	<-done
	q.Close()

	require.Equal(t, int64(total), consumed.Load(), "consumed")
	require.Equal(t, -1, firstUnseen(seen), "value never delivered")
}

// BenchmarkQueueHandoff measures the egress hand-off both underlay providers now use:
// producers Enqueue while one consumer drains with a blocking Dequeue
// followed by a non-blocking TryDequeue batch fill, exactly as the send loop does.
// chan is the inet path, ring is the AF_XDP path. P=1 is a single link
// (one processor feeds one sender); P=4 is a shared egress queue (several
// processors, one sender).
func BenchmarkQueueHandoff(b *testing.B) {
	const batch = 64
	for _, producers := range []int{1, 4} {
		b.Run(fmt.Sprintf("chan/P=%d", producers), func(b *testing.B) {
			benchQueueHandoff(b, producers, batch, chanq.New[int](8192))
		})
		b.Run(fmt.Sprintf("ring/P=%d", producers), func(b *testing.B) {
			benchQueueHandoff(b, producers, batch, lfring.New[int](8192))
		})
	}
}

// benchQueueHandoff drives exactly b.N items through the queue across `producers`
// producer goroutines and one consumer that drains in batches of `batch`.
func benchQueueHandoff(b *testing.B, producers, batch int, q Queue[int]) {
	b.ReportAllocs()
	var claimed atomic.Int64 // work handed out to producers
	target := int64(b.N)
	done := make(chan struct{})
	var wg sync.WaitGroup
	b.ResetTimer()

	// Consumer: blocking first packet, then a non-blocking batch fill.
	go func() {
		consumed := int64(0)
		for consumed < target {
			if _, ok := q.Dequeue(); !ok {
				break
			}
			consumed++
			for i := 1; i < batch; i++ {
				if _, ok := q.TryDequeue(); !ok {
					break
				}
				consumed++
			}
		}
		close(done)
	}()

	for range producers {
		wg.Go(func() {
			for {
				start := claimed.Add(int64(batch)) - int64(batch)
				if start >= target {
					return
				}
				n := batch
				if start+int64(n) > target {
					n = int(target - start)
				}
				for range n {
					for !q.Enqueue(0) {
						yieldRetry()
					}
				}
			}
		})
	}
	wg.Wait()
	<-done
	q.Close()
}
