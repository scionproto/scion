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

// Package lfring provides a bounded, lock-free ring buffer and a queue built on it,
// for passing values between goroutines without a mutex.
//
// The design is Dmitry Vyukov's bounded MPMC queue. Each slot carries a sequence
// number that encodes whose turn it is. Producers and consumers coordinate with
// one compare-and-swap. It is safe for many producers and many consumers,
// and is FIFO across the ring as a whole.
//
// [Ring] never blocks. [Ring.TryPush] returns false when it cannot take the value and
// [Ring.TryPop] returns false when it cannot supply one. Either can fail while the ring
// is neither full nor empty: a goroutine claims its slot by CAS and publishes it
// a moment later, and until then the slot reads as taken to the other side.
// A caller that must not lose a value has to retry:
//
//	for !r.TryPush(v) {
//		runtime.Gosched()
//	}
//
// Dropping the value instead is a leak when the ring holds a fixed set of items,
// such as a pool of packet buffers. The push that reported full would have
// succeeded a moment later, and nothing else holds the value any more.
//
// Such a retry loop should call [runtime.Gosched] between tries. There is nothing
// to sleep on here. The loop is waiting for another goroutine to finish claiming
// and publishing a slot, and that goroutine needs a CPU to finish. Gosched gives it one.
// A loop without Gosched keeps the CPU until Go's scheduler preempts it,
// which it does only after the goroutine has run for about 10 ms, and blocks the
// goroutine it waits for that whole time. The router makes this worse.
// It runs as many busy goroutines as the machine has cores.
// No CPU sits idle waiting to pick the work up.
//
// A retry loop like this one is the only good reason to call [runtime.Gosched].
//
// [Ring] has no way to wait. A consumer with nothing else to do would have to
// call [Ring.TryPop] in a loop and hold a core at 100% even while no value arrives.
// [Queue] exists for that consumer: [Queue.Dequeue] spins a few times to cover
// a short gap, then parks until a producer wakes it. Use [Ring] directly when the
// caller already has other work to do on an empty queue.
package lfring
