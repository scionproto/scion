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

	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// PollingPolicy describes how SCIOND should be polled, taking into account
// various aspects such as number of paths and the existence of a filtering
// policy. The PollingPolicy decides when SCIOND should be queried next, and
// which flags to be set.
type PollingPolicy interface {
	// UpdateState reconfigures the polling policy based on availablePaths.
	UpdateState(availablePaths spathmeta.AppPathSet)
	// PollNow triggers a new query now, irrespective of other timers.
	PollNow()
	// PollC returns the channel that is written to whenever the policy
	// dictates a new poll. Ticks are dropped if the channel is full.
	PollC() <-chan sciond.PathReqFlags
	// Destroy shuts down any running goroutines.
	Destroy()
}

func NewPollingPolicy(haveFilter bool, timers Timers) PollingPolicy {
	signalingChan := make(chan sciond.PathReqFlags, 1)
	initialParams := PollingParameters{interval: timers.NormalRefire}
	return &DefaultPollingPolicy{
		haveFilter:    haveFilter,
		timers:        timers,
		signalingChan: signalingChan,
		params:        initialParams,
		runner:        StartPeriodic(initialParams, signalingChan),
	}
}

type DefaultPollingPolicy struct {
	haveFilter    bool
	timers        Timers
	signalingChan chan sciond.PathReqFlags
	params        PollingParameters

	runnerMtx sync.Mutex
	runner    *periodic.Runner
}

func (pp *DefaultPollingPolicy) UpdateState(availablePaths spathmeta.AppPathSet) {
	parameters := pp.getPollingParams(availablePaths)
	if parameters != pp.params {
		pp.params = parameters
		pp.runner.Stop()

		pp.runnerMtx.Lock()
		defer pp.runnerMtx.Unlock()
		pp.runner = StartPeriodic(pp.params, pp.signalingChan)
	}
}

func (pp *DefaultPollingPolicy) getPollingParams(paths spathmeta.AppPathSet) PollingParameters {
	noPaths := len(paths) == 0
	waitDuration := pp.timers.GetWait(noPaths)
	flags := sciond.PathReqFlags{}
	if noPaths && pp.haveFilter {
		flags.Refresh = true
	}
	return PollingParameters{flags: flags, interval: waitDuration}
}

func (pp *DefaultPollingPolicy) PollNow() {
	// Protect access to runner, which might get changed during a state change.
	pp.runnerMtx.Lock()
	defer pp.runnerMtx.Unlock()
	pp.runner.TriggerRun()
}

func (pp *DefaultPollingPolicy) PollC() <-chan sciond.PathReqFlags {
	return pp.signalingChan
}

func (pp *DefaultPollingPolicy) Destroy() {
	pp.runnerMtx.Lock()
	defer pp.runnerMtx.Unlock()
	pp.runner.Stop()
}

type PollingParameters struct {
	flags    sciond.PathReqFlags
	interval time.Duration
}

func StartPeriodic(params PollingParameters, ch chan sciond.PathReqFlags) *periodic.Runner {
	return periodic.StartPeriodicTask(
		&taskPeriodicChannelWriter{ch: ch, flags: params.flags},
		periodic.NewTicker(params.interval),
		time.Hour, // Effectively forever, as the task is short and can never block
	)
}

// taskPeriodicChannelWriter writes flags to ch every time its Run method is
// called. If the channel is full, the flags are discarded.
type taskPeriodicChannelWriter struct {
	ch    chan sciond.PathReqFlags
	flags sciond.PathReqFlags
}

func (task *taskPeriodicChannelWriter) Run(_ context.Context) {
	select {
	case task.ch <- task.flags:
	default:
	}
}
