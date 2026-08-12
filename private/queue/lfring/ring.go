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

import "sync/atomic"

// cacheLine is the padding used to keep the hot producer and consumer indices
// off one another's cache line.
//
// It is the widest line among the targets that matter:
// Go's internal/cpu uses 128 on arm64 and ppc64 and 64 on amd64.
// Two fields 128 bytes apart are on separate lines under both.
// Padding to 64 would leave enq and deq sharing a line on arm64 whenever the ring
// lands on an odd 64-byte offset, which Go's allocator gives no control over.
const cacheLine = 128

// cell is one slot of the ring. seq is the synchronization point: it both orders
// the non-atomic val access (a store-release / load-acquire pair) and encodes
// the slot's state (free for the producer at position p, or filled for the consumer).
type cell[T any] struct {
	seq atomic.Uint64
	val T
}

// Ring is a bounded, lock-free MPMC (Multiple Producer Multiple Consumer) ring buffer
// holding values of type T.
//
// WARNING:
//   - The zero value is not usable; construct one with [NewRing].
//   - A Ring must not be copied after first use.
type Ring[T any] struct {
	// mask and cells are read by every operation and never written after construction.
	// They sit ahead of the two hot indices so that a writer
	// on enq or deq cannot invalidate the line they are read from.
	mask  uint64
	cells []cell[T]
	_     [cacheLine - 32]byte
	enq   atomic.Uint64
	_     [cacheLine - 8]byte
	deq   atomic.Uint64
	// Trailing pad: nothing the allocator places after the ring shares deq's line.
	_ [cacheLine - 8]byte
}

// MaxCapacity is the largest capacity [NewRing] and [New] accept.
// It is the largest power of two that fits the rounding.
const MaxCapacity = 1 << 30

// NewRing returns a ring whose capacity is rounded up to a power of two.
// Capacity is clamped to [2, MaxCapacity]. Use [Ring.Cap] to read the effective value.
func NewRing[T any](capacity int) *Ring[T] {
	size := roundUpPow2(capacity)
	r := &Ring[T]{
		mask:  uint64(size - 1),
		cells: make([]cell[T], size),
	}
	for i := range r.cells {
		r.cells[i].seq.Store(uint64(i))
	}
	return r
}

// roundUpPow2 returns the smallest power of two >= v, clamped to [2, MaxCapacity].
// The clamp keeps the doubling from overflowing, which would
// otherwise yield a zero-length cell slice.
func roundUpPow2(v int) uint32 {
	if v < 2 {
		return 2
	}
	if v > MaxCapacity {
		return MaxCapacity
	}
	u := uint32(v)
	u--
	u |= u >> 1
	u |= u >> 2
	u |= u >> 4
	u |= u >> 8
	u |= u >> 16
	return u + 1
}

// Cap returns the ring's capacity (a power of two).
func (r *Ring[T]) Cap() int {
	return int(r.mask + 1)
}

// Len returns an approximate number of queued elements. It is only a snapshot and may
// be stale the instant it returns; use it for metrics/heuristics, not for correctness.
func (r *Ring[T]) Len() int {
	deq, enq := r.deq.Load(), r.enq.Load()
	if enq < deq {
		return 0
	}
	return min(int(enq-deq), r.Cap())
}

// TryPush enqueues v. ok is true on success, or false if the ring is full.
// Safe to call from multiple producer goroutines concurrently.
func (r *Ring[T]) TryPush(v T) (ok bool) {
	pos := r.enq.Load()
	for {
		c := &r.cells[pos&r.mask]
		seq := c.seq.Load()
		switch dif := int64(seq) - int64(pos); {
		case dif == 0:
			// Slot is free at this position; try to claim it.
			if r.enq.CompareAndSwap(pos, pos+1) {
				c.val = v
				c.seq.Store(pos + 1) // publish to consumers (release)
				return true
			}
			// Another producer took this position. Move to the one it left.
			// Re-reading the same cell would spin until that producer publishes,
			// because the slot reads as free until then.
			pos = r.enq.Load()
		case dif < 0:
			return false // full: consumer has not freed this lap's slot yet
		default:
			pos = r.enq.Load() // another producer advanced; retry
		}
	}
}

// TryPop dequeues the oldest value. ok is false if the ring is empty.
// Safe to call from multiple consumer goroutines concurrently.
func (r *Ring[T]) TryPop() (v T, ok bool) {
	pos := r.deq.Load()
	for {
		c := &r.cells[pos&r.mask]
		seq := c.seq.Load()
		switch dif := int64(seq) - int64(pos+1); {
		case dif == 0:
			if r.deq.CompareAndSwap(pos, pos+1) {
				v = c.val
				var zero T
				c.val = zero                  // drop our reference before freeing
				c.seq.Store(pos + r.mask + 1) // free slot for the next lap (release)
				return v, true
			}
			// Another consumer took this position. Move to the one it left.
			pos = r.deq.Load()
		case dif < 0:
			return v, false // empty
		default:
			pos = r.deq.Load()
		}
	}
}

// PushBatch pushes as many of vs as fit and returns the count pushed (0..len).
// It amortizes call overhead. Each element is an independent lock-free push.
// A partial push leaves the tail of vs unqueued.
func (r *Ring[T]) PushBatch(vs []T) (n int) {
	for i := range vs {
		if !r.TryPush(vs[i]) {
			return i
		}
	}
	return len(vs)
}

// PopBatch pops up to len(dst) values into dst and returns the count popped.
func (r *Ring[T]) PopBatch(dst []T) (n int) {
	for i := range dst {
		v, ok := r.TryPop()
		if !ok {
			return i
		}
		dst[i] = v
	}
	return len(dst)
}
