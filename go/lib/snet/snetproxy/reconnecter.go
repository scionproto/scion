// Copyright 2018 ETH Zurich
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

package snetproxy

import (
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

// Use a var here to allow tests to inject shorter intervals for fast testing.
var (
	DefaultTickerInterval = time.Second
)

type Reconnecter interface {
	Reconnect(timeout time.Duration) (snet.Conn, error)
	Stop()
}

var _ Reconnecter = (*TickingReconnecter)(nil)

type TickingReconnecter struct {
	mtx sync.Mutex
	// XXX(scrye): reconnectF does not support cancellation because adding
	// context-aware dials in reliable socket is tricky. This can make stopping
	// the reconnecter take significant time, depending on the timeout of the
	// reconnection function.
	reconnectF func(timeout time.Duration) (snet.Conn, error)
	state      *State
	stopping   *AtomicBool
}

// NewTickingReconnecter creates a new dispatcher reconnecter. Calling
// Reconnect in turn calls f periodically to obtain a new connection to the
// dispatcher,
func NewTickingReconnecter(f func(timeout time.Duration) (snet.Conn, error)) *TickingReconnecter {
	return &TickingReconnecter{
		reconnectF: f,
		stopping:   &AtomicBool{},
	}
}

// Reconnect repeatedly attempts to reestablish a connection to the dispatcher,
// subject to timeout. Attempts that receive dispatcher connection errors are
// followed by reattempts. Critical errors (e.g., port mismatches) return
// immediately.
func (r *TickingReconnecter) Reconnect(timeout time.Duration) (snet.Conn, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	start := time.Now()
	t := time.NewTicker(DefaultTickerInterval)
	defer t.Stop()

	timeoutExpired := afterTimeout(timeout)
	for r.stopping.IsFalse() {
		newTimeout, ok := getNewTimeout(timeout, start)
		if !ok {
			return nil, common.NewBasicError(ErrReconnecterTimeoutExpired, nil)
		}
		conn, err := r.reconnectF(newTimeout)
		switch {
		case isSysError(err):
			// Wait until next tick to retry. If the overall timeout expires
			// before the next tick, return immediately with an error.
			// time.Ticker will ensure that no more than one attempt is made
			// per interval (even if the reconnection function takes longer
			// than the interval).
			select {
			case <-t.C:
			case <-timeoutExpired:
				return nil, common.NewBasicError(ErrReconnecterTimeoutExpired, nil)
			}
			continue
		case err != nil:
			return nil, err
		default:
			return conn, nil
		}
	}
	return nil, common.NewBasicError(ErrReconnecterStopped, nil)
}

// Stop shuts down the reconnection attempt (if any), and waits for the
// reconnecting goroutine to finish.
//
// It is safe to call Stop while Reconnect is running.
func (r *TickingReconnecter) Stop() {
	r.stopping.Set(true)
	// Grab lock to make sure the reconnection function finished
	r.mtx.Lock()
	r.mtx.Unlock()
}

func getNewTimeout(timeout time.Duration, start time.Time) (time.Duration, bool) {
	if timeout == 0 {
		return 0, true
	}
	newTimeout := timeout - time.Now().Sub(start)
	if newTimeout > 0 {
		return newTimeout, true
	}
	return 0, false
}

// afterTimeout waits for the timeout to elapse and then sends the current
// time on the returned channel. If the timeout is 0, the current time is never
// sent.
func afterTimeout(timeout time.Duration) <-chan time.Time {
	var timeoutExpired <-chan time.Time
	if timeout != 0 {
		timeoutExpired = time.After(timeout)
	}
	return timeoutExpired
}
