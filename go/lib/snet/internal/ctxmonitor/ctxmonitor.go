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

package ctxmonitor

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/log"
)

// Monitor implements deadline-aware context creation. Implementations
// guarantee that any contexts returned by the methods are cancelled when the
// deadline passed in through SetDeadline is reached. Any change to deadline is
// respected, including setting it into the past.
//
// Monitor is targeted for use in libraries that implement both deadline-aware
// logic (e.g., net.Conn and net.PacketConn implementations), but also have
// context-aware internals.
//
// IMPORTANT: If the deadline set through SetDeadline is reached and a
// context is canceled, the error will be context.Canceled instead
// of context.DeadlineExceeded.
type Monitor interface {
	// WithDeadline creates a context similarly to context.WithDeadline, except
	// the newly created context is also subject to any deadlines set by
	// SetDeadline.
	WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc)
	// WithTimeout returns WithDeadline(parent, time.Now().Add(timeout)).
	WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc)
	// SetDeadline sets an absolute time after which all tracked contexts are
	// canceled. SetDeadline can be set in the past to mark everything as
	// done, or can be extended in the future through repeated calls.
	//
	// A 0 value for the deadline means contexts will never be canceled by the monitor.
	SetDeadline(deadline time.Time)
	// Count returns the number of contexts in the monitor that haven't expired or
	// been canceled yet.
	Count() int
}

type ctxMap map[context.Context]context.CancelFunc

var _ Monitor = (*monitor)(nil)

type monitor struct {
	deadlineRunner *DeadlineRunner

	mtx      sync.Mutex
	ctxs     ctxMap
	deadline time.Time
}

func NewMonitor() Monitor {
	m := &monitor{
		ctxs: make(ctxMap),
	}
	m.deadlineRunner = NewDeadlineRunner(m.clean)
	return m
}

func (m *monitor) WithTimeout(ctx context.Context,
	timeout time.Duration) (context.Context, context.CancelFunc) {

	return m.WithDeadline(ctx, time.Now().Add(timeout))
}

func (m *monitor) WithDeadline(ctx context.Context,
	deadline time.Time) (context.Context, context.CancelFunc) {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	subCtx, cancelF := context.WithDeadline(ctx, deadline)
	if m.deadlinePassed(deadline) {
		// Deadline has already passed, all new contexts are already Done
		cancelF()
		return subCtx, cancelF
	}
	m.ctxs[subCtx] = cancelF
	return subCtx, m.createDeletionLocked(subCtx, cancelF)
}

func (m *monitor) deadlinePassed(ctxDeadline time.Time) bool {
	return !m.deadline.Equal(time.Time{}) && m.deadline.Before(ctxDeadline)
}

// createDeletionLocked returns a cancellation function that also deletes the
// context information from the internal monitor map. This ensures proper
// cleanup when contexts are canceled even if the monitor deadline is never
// reached.
func (m *monitor) createDeletionLocked(ctx context.Context,
	cancelF context.CancelFunc) context.CancelFunc {

	return func() {
		m.mtx.Lock()
		// If the map reference was changed, this is a no-op (and the entry in
		// the old map will be GC'd together with the map)
		delete(m.ctxs, ctx)
		m.mtx.Unlock()
		cancelF()
	}
}

func (m *monitor) SetDeadline(deadline time.Time) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.deadline = deadline
	m.deadlineRunner.SetDeadline(deadline)
}

func (m *monitor) clean() {
	m.mtx.Lock()
	for _, cancelF := range m.ctxs {
		cancelF()
	}
	m.ctxs = make(ctxMap)
	m.mtx.Unlock()
}

func (m *monitor) Count() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	var count int
	for ctx := range m.ctxs {
		if ctx.Err() == nil {
			count += 1
		}
	}
	return count
}

// DeadlineRunner runs a callback function in a goroutine whenever the deadline
// is reached. The function is called at most once per call to SetDeadline.
//
// Multiple executions of the callback can happen at once, so the callback must
// ensure proper synchronization.
//
// SetDeadline is safe to call from multiple goroutines.
type DeadlineRunner struct {
	f     func()
	mtx   sync.Mutex
	timer *time.Timer
}

func NewDeadlineRunner(f func()) *DeadlineRunner {
	return &DeadlineRunner{f: f}
}

func (r *DeadlineRunner) SetDeadline(deadline time.Time) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.timer != nil {
		// We don't care about the return value of stop. If the function called
		// by AfterFunc executed already, it means the old deadline was
		// respected and we may execute it again according to the new deadline.
		// Otherwise, we cancel the old timer and just wait for the new one.
		r.timer.Stop()
	}
	if deadline.Equal(time.Time{}) {
		return
	}
	r.timer = time.AfterFunc(deadline.Sub(time.Now()), func() {
		defer log.LogPanicAndExit()
		r.f()
	})
}
