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

// This file measures what spinning costs, and clock time cannot show that.
// A consumer that spins returns quickly and looks good in ns/op while it keeps a
// CPU busy the whole time. syscall.Getrusage reports how much CPU time the
// process really used, which is the number that makes the cost visible.
//
// Windows and plan9 have no Getrusage. Nothing else in lfring depends on the platform.
// The constraint therefore sits on this file rather than the package.
// Without it those two targets cannot build the package's tests at all.

//go:build unix

package lfring

import (
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// gaps are the producer inter-arrival times the spin sweep runs at.
// They bracket the router's egress queue: sub-microsecond at AF_XDP rates,
// tens of microseconds on an idle link.
var gaps = []time.Duration{
	0,
	200 * time.Nanosecond,
	1 * time.Microsecond,
	5 * time.Microsecond,
	50 * time.Microsecond,
}

// busyWait burns d without yielding, which is how a real producer occupies the
// gap between two packets. time.Sleep would park the producer and measure the
// scheduler instead.
func busyWait(d time.Duration) {
	if d == 0 {
		return
	}
	end := time.Now().Add(d)
	for time.Now().Before(end) {
	}
}

// produce enqueues into the queue every gap until stop is closed.
// It re-checks stop while the ring is full. Without that,
// the goroutine outlives its sub-benchmark and burns a core for the rest of the run,
// which slows every later sub-benchmark.
func produce(enqueue func(int) bool, gap time.Duration, stop <-chan struct{}) {
	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		default:
		}
		busyWait(gap)
		for !enqueue(i) {
			select {
			case <-stop:
				return
			default:
			}
			// The ring is full. Only the consumer frees a slot, and it needs
			// a CPU to do it. Yield, as the package doc explains. Without
			// this, the dequeue being measured waits on the scheduler.
			runtime.Gosched()
		}
	}
}

// cpuNanos returns the process CPU time (user+sys) consumed so far.
func cpuNanos() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return ru.Utime.Nano() + ru.Stime.Nano()
}

// BenchmarkDequeueSpins measures what dequeueSpins trades off. One producer
// enqueues every gap nanoseconds and one consumer calls Dequeue. The ring is
// empty whenever the consumer arrives first, which is the only situation the
// spin count affects. BenchmarkQueueHandoff never reaches it.
//
// It reports two metrics:
//
//   - ns/dequeue: time inside Dequeue. A spin that outlasts the gap returns
//     without parking and is fast. A shorter one parks and pays a wakeup.
//   - cpu-ns/op: process CPU per handoff. A spin that outlasts the gap burns
//     CPU that a parked consumer would not.
//
// To sweep the spin count, edit dequeueSpins and re-run.
// The table on that constant came from such a sweep.
//
// One producer only. The router's egress queue has several processors feeding
// one sender, and a sweep at higher producer counts has not been run.
func BenchmarkDequeueSpins(b *testing.B) {
	for _, gap := range gaps {
		b.Run(fmt.Sprintf("gap=%v/spins=%d", gap, dequeueSpins), func(b *testing.B) {
			q := New[int](1024)
			stop := make(chan struct{})
			go produce(q.Enqueue, gap, stop)

			// Drain what the producer wrote while starting up.
			for {
				if _, ok := q.TryDequeue(); !ok {
					break
				}
			}

			cpu0 := cpuNanos()
			var inDequeue time.Duration
			b.ResetTimer()
			for range b.N {
				t0 := time.Now()
				q.Dequeue()
				inDequeue += time.Since(t0)
			}
			b.StopTimer()
			cpu1 := cpuNanos()
			close(stop)

			b.ReportMetric(float64(inDequeue.Nanoseconds())/float64(b.N), "ns/dequeue")
			b.ReportMetric(float64(cpu1-cpu0)/float64(b.N), "cpu-ns/op")
		})
	}
}
