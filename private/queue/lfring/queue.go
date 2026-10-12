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

package lfring

import (
	"runtime"
	"sync/atomic"
)

// dequeueSpins is how many times [Queue.Dequeue] polls an empty ring before it parks.
// Parking and waking a goroutine costs more than a poll.
// A consumer that parks on every brief gap loses throughput.
// One that polls for too long burns CPU unnecessarily; it's a fine balance.
//
// BenchmarkDequeueSpins, ns inside Dequeue at a zero producer gap, Xeon w5-2455X:
//
//	spins  0      1     2     4     8     16    32    128   512
//	ns     127.5  55.9  56.5  56.1  55.8  55.8  56.7  56.9  56.4
//
// 0 skips the fast path entirely. Every Dequeue then announces the park with two
// sequentially-consistent stores and may sleep, even when a value is waiting.
// That costs more than twice as much.
// Every value from 1 up measures the same. With producer gaps of 1 us and
// above the spin does not matter and every value is the same.
//
// The router benchmark is too noisy to decide. //acceptance/router_benchmark on
// a 25G BlueField-2 (afxdp, mix, 6 router cores, 192 B packets) forwards:
//
//   - 2.16M pps at 1 spin
//   - 2.13M pps at 2 spins
//   - 2.11M pps at 32 spins
//
// Small packets (192B) reach the highest pps, where the gaps between packets are
// shortest and the spin matters most. The spread is still only 2.4%,
// and two runs of the same value differ by up to 8%.
// The three values ran in turn, seven times each. None of them won.
//
// 1 is the smallest value that avoids the cost of 0. Nothing above it measures better,
// on either benchmark.
const dequeueSpins = 1

// Queue is a bounded producer/consumer queue on the lock-free [Ring],
// which can also sleep when idle. Use it for a queue that stays busy:
// [Queue.Enqueue] and [Queue.Dequeue] then use only the ring's atomics and take no lock.
//
// On an empty queue, [Queue.Dequeue] checks dequeueSpins more times, then sleeps
// until a producer wakes it. A short gap costs a few checks. An idle queue uses no CPU.
// On a queue that is usually empty the checks always fail. Use a channel there.
//
// The ring underneath is MPMC and stays MPMC. Many goroutines may enqueue, and
// many may call [Queue.TryDequeue], which is [Ring.TryPop] and nothing more.
//
// WARNING: exactly one goroutine may call [Queue.Dequeue]. Break that and a
// consumer sleeps forever with values waiting for it, which no error reports.
//
// Waiting is the one thing Queue adds on top of the ring, and it is built for a
// single waiter: one flag saying a consumer is parked, and one wakeup token to
// spend. Park two consumers and a producer wakes one of them. That one clears the
// flag as it leaves. The next producer reads the cleared flag and stays quiet, and
// the consumer still parked sleeps on while values pile up in the ring. To have
// several goroutines consume, poll [Ring.TryPop] directly, or give each of them
// its own Queue.
//
// [queue.Queue] asks for a single consumer across both methods. That is the rule
// to keep to in code that switches between implementations.
type Queue[T any] struct {
	ring *Ring[T]
	// notEmpty carries a single coalesced wakeup token (cap 1) from a producer
	// to a parked consumer. Touched only when the consumer is parked.
	notEmpty chan struct{}
	// done is closed by Close to wake a parked consumer.
	done chan struct{}
	// waiting is set by the consumer while it is about to park or parked.
	// A producer signals only when a wakeup is needed.
	// The consumer is the single writer. Producers only read it.
	waiting atomic.Bool
	closed  atomic.Bool
}

// New rounds capacity up to a power of two and clamps it to
// [2, MaxCapacity] (see [NewRing]). [Queue.Cap] reports the effective value.
func New[T any](capacity int) *Queue[T] {
	return &Queue[T]{
		ring:     NewRing[T](capacity),
		notEmpty: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// signal drops one wakeup token into notEmpty. It never blocks.
// The capacity of 1 coalesces concurrent producers into at most one token,
// and the consumer still sees it.
func (q *Queue[T]) signal() {
	select {
	case q.notEmpty <- struct{}{}:
	default:
	}
}

// Enqueue implements [queue.Writer]. false does not prove the queue is full:
// the ring reports full for a slot a consumer has claimed but not yet released.
func (q *Queue[T]) Enqueue(v T) bool {
	if !q.ring.TryPush(v) {
		return false
	}
	if q.waiting.Load() {
		q.signal()
	}
	return true
}

// EnqueueBlocking implements [queue.Writer]. It keeps retrying rather than going
// to sleep, and [Queue.Close] does not release it. A caller that enqueues into a
// full queue whose consumer has stopped retries forever.
// The contract puts that case outside the queue, and this is not a hot-path method.
func (q *Queue[T]) EnqueueBlocking(v T) {
	for !q.ring.TryPush(v) {
		// There is nothing to sleep on. Only a consumer frees a slot, and it
		// needs a CPU to do that. Gosched gives it one. See the note on retry
		// loops in the package doc.
		runtime.Gosched()
	}
	if q.waiting.Load() {
		q.signal()
	}
}

// TryDequeue implements [queue.Reader]. It is [Ring.TryPop] and inherits both of
// that method's properties: any number of goroutines may call it,
// and false does not prove the queue is empty.
// It can report empty while a producer is midway through a push.
func (q *Queue[T]) TryDequeue() (v T, ok bool) {
	return q.ring.TryPop()
}

// Dequeue implements [queue.Reader].
//
// WARNING: exactly one goroutine may call it. See the note on [Queue]:
// the ring is MPMC, the waiting built on top of it is not.
func (q *Queue[T]) Dequeue() (v T, ok bool) {
	// Fast path: a short spin covers the busy case with no parking.
	for range dequeueSpins {
		if v, ok := q.ring.TryPop(); ok {
			return v, true
		}
	}
	// Slow path: announce we are about to park, re-check, then sleep until a
	// producer signals or the queue is closed. The waiting flag is set before
	// the re-check so a producer that pushes after our miss is guaranteed to signal us
	// (sequentially-consistent atomics order the store before the producer's load).
	for {
		q.waiting.Store(true)
		if v, ok := q.ring.TryPop(); ok {
			q.waiting.Store(false)
			return v, true
		}
		if q.closed.Load() {
			// Closed. The contract has producers stop before Close.
			// No push is still in flight and nothing more can arrive.
			// This is the consumer's stop signal.
			// TryPop alone would not prove the queue drained:
			// it reports empty while a producer sits between its CAS and
			// its publishing store.
			q.waiting.Store(false)
			var zero T
			return zero, false
		}
		select {
		case <-q.notEmpty:
		case <-q.done:
		}
		q.waiting.Store(false)
	}
}

// Close implements [queue.Queue]. Repeated calls are safe.
func (q *Queue[T]) Close() {
	if !q.closed.Swap(true) {
		close(q.done)
	}
}

// Len implements [queue.Queue]. The count is approximate.
func (q *Queue[T]) Len() int { return q.ring.Len() }

// Cap implements [queue.Queue]. It reports the rounded capacity,
// not the one passed to [New].
func (q *Queue[T]) Cap() int { return q.ring.Cap() }
