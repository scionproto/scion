// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package priority_test

import (
	"sync/atomic"
	"testing"
	"time"

	pr "github.com/scionproto/scion/router/priority"
	"github.com/stretchr/testify/assert"
)

func TestReadAsync(t *testing.T) {
	queuesOut := newPriorityQueue(2)
	queues := toInChannels(queuesOut)
	v, ok := pr.ReadAsync(queues)
	assert.Equal(t, false, ok)
	assert.Equal(t, 0, v)

	// Send one value to each queue.
	queuesOut[1] <- 101
	queuesOut[0] <- 10

	// Should return the value from queue 0.
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 10, v)
	// Should return the value from queue 1.
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 101, v)

	// Should be empty now.
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, false, ok)

	// Send to best-effort queue.
	queuesOut[1] <- 102
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 102, v)

	// Should be empty again.
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, false, ok)

	// Send to priority queue only.
	queuesOut[0] <- 11
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 11, v)

	// Should be empty again.
	v, ok = pr.ReadAsync(queues)
	assert.Equal(t, false, ok)
}

func TestReadBlocking(t *testing.T) {
	queuesOut := newPriorityQueue(2)
	queues := toInChannels(queuesOut)
	// Send values.
	queuesOut[1] <- 100
	queuesOut[0] <- 10

	// Should not block.
	v, ok := pr.ReadBlocking(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 10, v)
	v, ok = pr.ReadBlocking(queues)
	assert.Equal(t, true, ok)
	assert.Equal(t, 100, v)

	// This should block until new values arrive.
	finishedRead := atomic.Uint32{}
	go func() {
		for {
			v, ok = pr.ReadBlocking(queues)
			finishedRead.Add(1)
		}
	}()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, uint32(0), finishedRead.Load())

	// Send to priority.
	v, ok = 0, false
	queuesOut[0] <- 11
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, uint32(1), finishedRead.Load())
	assert.Equal(t, true, ok)
	assert.Equal(t, 11, v)

	// Send to best-effort.
	v, ok = 0, false
	queuesOut[1] <- 101
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, uint32(2), finishedRead.Load())
	assert.Equal(t, true, ok)
	assert.Equal(t, 101, v)

	// No more values.
	v, ok = 0, false
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, uint32(2), finishedRead.Load())
}

func TestReadBlockingReflect(t *testing.T) {
	queuesOut := newPriorityQueue(2)
	queues := toInChannels(queuesOut)

	// Send one value to each queue.
	queuesOut[1] <- 101
	queuesOut[0] <- 10

	v, ok := pr.ReadBlockingReflect(queues)
	assert.Equal(t, true, ok)
	t.Logf("v = %d", v)
	v, ok = pr.ReadBlockingReflect(queues)
	assert.Equal(t, true, ok)
	t.Logf("v = %d", v)
}

func BenchmarkReadBlocking(b *testing.B) {
	b.Run("readblocking", func(b *testing.B) {
		queuesOut := newPriorityQueue(2)
		queues := toInChannels(queuesOut)
		go func() {
			for {
				queuesOut[0] <- 0
				queuesOut[1] <- 1
			}
		}()
		for range b.N {
			pr.ReadBlocking(queues)
		}
	})
	b.Run("reflect", func(b *testing.B) {
		queuesOut := newPriorityQueue(2)
		queues := toInChannels(queuesOut)
		go func() {
			for {
				queuesOut[0] <- 0
				queuesOut[1] <- 1
			}
		}()
		for range b.N {
			pr.ReadBlockingReflect(queues)
		}
	})
	b.Run("reflect-wrapper", func(b *testing.B) {
		queuesOut := newPriorityQueue(2)
		queues := toInChannels(queuesOut)
		wrapper := pr.NewReflectWrapper(queues)
		go func() {
			for {
				queuesOut[0] <- 0
				queuesOut[1] <- 1
			}
		}()
		for range b.N {
			wrapper.ReadBlocking()
		}
	})
}

func newPriorityQueue(channelsBufferSize int) [pr.QueueCount]chan int {
	var q [pr.QueueCount]chan int
	for i := range q {
		q[i] = make(chan int, channelsBufferSize)
	}
	return q
}

func toInChannels(q [pr.QueueCount]chan int) [pr.QueueCount]<-chan int {
	var ret [pr.QueueCount]<-chan int
	for i := range pr.QueueCount {
		ret[i] = q[i]
	}
	return ret
}
