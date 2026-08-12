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

package chanq

// Queue is a bounded producer/consumer queue backed by a buffered Go channel.
// A blocked [Queue.Dequeue] sleeps until a producer sends, and never spins.
type Queue[T any] struct {
	ch  chan T
	cap int
}

// New uses capacity exactly; unlike queue/lfring it does not round.
// A capacity of 0 gives an unbuffered channel, where [Queue.Enqueue] fails unless a
// consumer is already waiting. A negative capacity panics.
func New[T any](capacity int) *Queue[T] {
	return &Queue[T]{ch: make(chan T, capacity), cap: capacity}
}

// Enqueue implements [queue.Writer]. false means the queue is full.
// Enqueuing after [Queue.Close] panics, as sending on a closed channel does.
func (q *Queue[T]) Enqueue(v T) bool {
	select {
	case q.ch <- v:
		return true
	default:
		return false
	}
}

// EnqueueBlocking implements [queue.Writer]. It parks until there is room.
func (q *Queue[T]) EnqueueBlocking(v T) { q.ch <- v }

// Dequeue implements [queue.Reader].
func (q *Queue[T]) Dequeue() (v T, ok bool) {
	v, ok = <-q.ch
	return v, ok
}

// TryDequeue implements [queue.Reader]. ok is false once the queue is closed and drained,
// which is what the channel receive reports.
func (q *Queue[T]) TryDequeue() (v T, ok bool) {
	select {
	case v, ok = <-q.ch:
		return v, ok
	default:
		return v, false
	}
}

// Close implements [queue.Queue]. Calling it twice panics,
// as closing a closed channel does.
func (q *Queue[T]) Close() { close(q.ch) }

// Len implements [queue.Queue]. For a channel the count is exact.
func (q *Queue[T]) Len() int { return len(q.ch) }

// Cap implements [queue.Queue]. It reports the capacity passed to [New].
func (q *Queue[T]) Cap() int { return q.cap }
