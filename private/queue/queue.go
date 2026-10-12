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

// Writer is the send end of a [Queue]. Take it in place of a chan<-.
type Writer[T any] interface {
	// Enqueue is non-blocking and safe for multiple producers. It returns false
	// when v was not added. A false result does not prove the queue is full:
	// queue/lfring reports full for a slot a consumer has claimed but not yet
	// released. Callers that must not lose v have to retry rather than drop.
	Enqueue(v T) bool
	// EnqueueBlocking adds v, waiting until there is room. Not for the hot path;
	// it exists for rare callers (e.g. tests) that must not drop.
	EnqueueBlocking(v T)
}

// Reader is the receive end of a [Queue]. Take it in place of a <-chan.
type Reader[T any] interface {
	// Dequeue removes the oldest value, blocking until one is available.
	// ok is false only when the queue is closed and drained,
	// which is the consumer's signal to stop.
	Dequeue() (v T, ok bool)
	// TryDequeue removes the oldest value without blocking. ok is false when no
	// value is available. A false result does not prove the queue is empty:
	// queue/lfring reports empty for a slot a producer has claimed but not yet published.
	// Used to fill a batch after a blocking [Reader.Dequeue].
	TryDequeue() (v T, ok bool)
}

// Queue is a bounded, single-consumer producer/consumer queue. Pick the
// implementation that fits. Use queue/chanq for a queue that is usually empty,
// where the consumer sleeps until a producer sends. Use queue/lfring for a queue
// that stays busy, where the ring takes no lock.
//
// Hold a Queue where the code owns both ends. Pass [Reader] or [Writer] to the
// goroutine that only consumes or only produces.
//
// The implementations are interchangeable for code that keeps to this contract:
//   - Many producers may call [Writer.Enqueue] and [Writer.EnqueueBlocking]
//     concurrently.
//   - Exactly one consumer calls [Reader.Dequeue] and [Reader.TryDequeue].
//   - [Queue.Close] is called once, after producers have stopped, to end the
//     consumer's blocking [Reader.Dequeue]. [Writer.Enqueue] after
//     [Queue.Close] is a caller bug (same rule as closing a channel).
//
// Break the contract and the two diverge. Do not rely on either outcome.
// queue/chanq panics on a second [Queue.Close] and on [Writer.Enqueue] after
// [Queue.Close]; queue/lfring accepts both and strands the value instead.
// [Writer.EnqueueBlocking] into a full queue whose consumer has stopped parks
// forever on queue/chanq and spins on queue/lfring.
type Queue[T any] interface {
	Reader[T]
	Writer[T]
	// Close signals that no more values will be enqueued and wakes a consumer
	// blocked in [Reader.Dequeue]. Call it once.
	Close()
	// Len returns an approximate queued count (metrics/heuristics only).
	Len() int
	// Cap returns the effective capacity, which may exceed the one requested at
	// construction: queue/lfring rounds up to a power of two.
	Cap() int
}
