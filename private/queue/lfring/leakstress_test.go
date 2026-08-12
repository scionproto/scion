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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// circulate models the packet pool: a fixed token set, and a ring sized to hold
// all of them. The ring never fills. Any lost token is therefore a leak.
// retryPush selects the PacketPool.Put policy under test.
func circulate(t *testing.T, retryPush bool) (lost uint64, left int) {
	const (
		tokens  = 1024
		workers = 8
		iters   = 200_000
	)
	r := NewRing[int](tokens)
	for i := range tokens {
		require.True(t, r.TryPush(i), "prefill %d", i)
	}

	var lostCount atomic.Uint64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range iters {
				v, ok := r.TryPop()
				if !ok {
					continue
				}
				if retryPush {
					for !r.TryPush(v) {
						// This models PacketPool.Put. The ring cannot be full here.
						// A failure means another worker is midway
						// through claiming a slot. Retry and yield,
						// as the package doc explains.
						runtime.Gosched()
					}
					continue
				}
				if !r.TryPush(v) {
					lostCount.Add(1) // Nothing else holds the token now.
				}
			}
		})
	}
	wg.Wait()
	return lostCount.Load(), r.Len()
}

// TestPutDiscardLeaks shows why a pool must not drop a value when
// [Ring.TryPush] fails. [Ring.TryPush] reports full on a ring that has room.
// Dropping there retires the value permanently.
func TestPutDiscardLeaks(t *testing.T) {
	lost, left := circulate(t, false)
	t.Logf("discard on failure: lost %d tokens, %d/1024 left", lost, left)
	if lost == 0 {
		t.Skip("no false-full this run; the race is timing dependent")
	}
	require.Equal(t, 1024-int(lost), left, "every lost token left the ring")
}

// TestPutRetryDoesNotLeak ensures retrying the push keeps every value.
func TestPutRetryDoesNotLeak(t *testing.T) {
	lost, left := circulate(t, true)
	require.Zero(t, lost, "retrying Put lost tokens")
	require.Equal(t, 1024, left, "tokens left in the ring after the run")
}
