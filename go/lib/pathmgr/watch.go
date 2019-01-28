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

func (factory *WatchFactory) New(sp *SyncPaths, bq *queryConfig, pp PollingPolicy) *WatchReference {
	ref := &WatchReference{parent: factory}
	factory.instances[ref] = &WatchRunner{
		sp:      sp,
		querier: bq,
		pp:      pp,
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

func (factory *WatchFactory) apply(f func(*WatchRunner)) {
	factory.mtx.RLock()
	defer factory.mtx.RUnlock()
	for _, w := range factory.instances {
		f(w)
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
		w.pp.UpdateState(w.sp.Load().APS)
		select {
		case <-w.closeC:
			w.pp.Destroy()
			return
		case flags := <-w.pp.PollC():
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
