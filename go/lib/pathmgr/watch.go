// Copyright 2019 ETH Zurich
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

package pathmgr

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// WatchFactory creates and tracks path watches, i.e., path polling goroutines.
type WatchFactory struct {
	timers Timers
	// mtx protects the map operations below
	mtx       sync.RWMutex
	instances map[*WatchReference]*WatchRunner
}

func NewWatchFactory(timers Timers) *WatchFactory {
	return &WatchFactory{
		instances: make(map[*WatchReference]*WatchRunner),
		timers:    timers,
	}
}

func (factory *WatchFactory) New(sp *SyncPaths, bq *queryConfig) *WatchReference {
	ref := &WatchReference{parent: factory}
	factory.instances[ref] = &WatchRunner{
		sp:      sp,
		querier: bq,
		pp:      NewPollingPolicy(bq.filter != nil, factory.timers),
		closeC:  make(chan struct{}),
	}
	return ref
}

func (factory *WatchFactory) destroy(ref *WatchReference) {
	factory.mtx.Lock()
	defer factory.mtx.Unlock()
	watch := factory.instances[ref]
	watch.Stop()
	delete(factory.instances, ref)
}

func (factory *WatchFactory) length() int {
	factory.mtx.RLock()
	defer factory.mtx.RUnlock()
	return len(factory.instances)
}

func (factory *WatchFactory) apply(f func(*SyncPaths)) {
	factory.mtx.RLock()
	defer factory.mtx.RUnlock()
	for _, w := range factory.instances {
		f(w.sp)
	}
}

func (factory *WatchFactory) run(ref *WatchReference) {
	// Run must execute outside the lock, because it is a long-running worker.
	watch := factory.getRunner(ref)
	if watch != nil {
		// The caller destroyed the reference before it got to run. Because the
		// polling loop usually runs in its own goroutine, this can happen if
		// the caller quickly calls destroy.
		watch.Run()
	}
}

func (factory *WatchFactory) getRunner(ref *WatchReference) *WatchRunner {
	factory.mtx.RLock()
	defer factory.mtx.RUnlock()
	return factory.instances[ref]
}

// WatchReference is a reference to an internal Watch managed by the
// PathManager. Call Run to start the goroutine associated with the watch, and
// call Destroy to stop it.
//
// Calling Run after a reference has been destroyed will result in a no-op.
type WatchReference struct {
	parent *WatchFactory
}

func (ref *WatchReference) Run() {
	ref.parent.run(ref)
}

func (ref *WatchReference) Destroy() {
	ref.parent.destroy(ref)
}

// WatchRunner polls SCIOND in accordance to a polling policy, updating a
// concurrency-safe store of paths after every poll.
//
// Call Stop to shut down the running goroutine. It is safe to call Stop
// multiple times from different goroutines.
type WatchRunner struct {
	pp      PollingPolicy
	sp      *SyncPaths
	querier *queryConfig
	closeC  chan struct{}
}

func (w *WatchRunner) Run() {
	for {
		timer := w.pp.ArmNextTrigger(w.sp.Load().APS)
		select {
		case <-w.closeC:
			timer.Stop()
			return
		case flags := <-w.pp.Drainer():
			ctx, cancelF := context.WithTimeout(context.Background(), DefaultQueryTimeout)
			w.sp.update(w.querier.Do(ctx, flags))
			cancelF()
		}
	}
}

func (w *WatchRunner) Stop() {
	select {
	case <-w.closeC:
	default:
		close(w.closeC)
	}
}

// PollingPolicy describes how SCIOND should be polled, taking into account
// various aspects such as number of paths and the existence of a filtering
// policy. The PollingPolicy decides when SCIOND should be queried next, and
// which flags to be set.
type PollingPolicy interface {
	// ArmNextTrigger schedules the next tick, as dictated by the policy. Use
	// the returned timer to clean up any resources.
	ArmNextTrigger(availablePaths spathmeta.AppPathSet) *time.Timer
	// Drainer returns the channel that is written to whenever the policy
	// dictates a new execution. Ticks can be dropped if the channel is full.
	// Callers should make sure that the policy is reevaluated after every
	// drain, thus ensuring that a new tick will arrive in the future.
	Drainer() <-chan sciond.PathReqFlags
}

func NewPollingPolicy(haveFilter bool, timers Timers) PollingPolicy {
	return &DefaultPollingPolicy{
		haveFilter:    haveFilter,
		timers:        timers,
		signalingChan: make(chan sciond.PathReqFlags, 1),
	}
}

type DefaultPollingPolicy struct {
	haveFilter    bool
	timers        Timers
	signalingChan chan sciond.PathReqFlags
}

func (pp *DefaultPollingPolicy) ArmNextTrigger(availablePaths spathmeta.AppPathSet) *time.Timer {
	noPaths := len(availablePaths) == 0
	waitDuration := pp.timers.GetWait(noPaths)
	timer := time.AfterFunc(waitDuration, func() {
		flags := sciond.PathReqFlags{}
		if noPaths && pp.haveFilter {
			flags.Refresh = true
		}
		select {
		case pp.signalingChan <- flags:
		default:
			// A tick already exists in the channel. This means that the reader
			// is guaranteed to drain the channel, and re-enter this function
			// in the future, so it is safe to discard.
		}
	})
	return timer
}

func (pp *DefaultPollingPolicy) Drainer() <-chan sciond.PathReqFlags {
	return pp.signalingChan
}

// queryConfig describes the persistent query information associated with a
// path polling loop.
type queryConfig struct {
	querier Querier
	src     addr.IA
	dst     addr.IA
	filter  *pathpol.Policy
}

func (bq *queryConfig) Do(ctx context.Context, flags sciond.PathReqFlags) spathmeta.AppPathSet {
	aps := bq.querier.Query(ctx, bq.src, bq.dst, flags)
	if bq.filter != nil {
		aps = bq.filter.Act(aps).(spathmeta.AppPathSet)
	}
	return aps
}
