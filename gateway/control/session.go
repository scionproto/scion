// Copyright 2020 Anapaya Systems
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

package control

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
)

type SessionMetrics struct {
	// PathChanges counts the number of times the path changed for this session.
	PathChanges metrics.Counter
}

// DataplaneSession represents a packet framer sending packets along a specific path.
type DataplaneSession interface {
	PktWriter
	// SetPaths can be used to change the paths on which packets are sent. If a path is invalid
	// or causes MTU issues, an error is returned.
	SetPaths([]snet.Path) error
	// Close informs the session it should shut down. It does not wait for the session to close.
	Close()
}

// Session represents a point-to-point association with a remote gateway that is subject to
// a path policy.
//
// Once the session is started, up and down events are read from the session monitor and forwarded
// on the events channel.
//
// If the reader of the events channel is slow, Session internals might block to avoid the event
// being lost.
type Session struct {
	// ID is the ID of the session. It's used for debugging and the status page.
	ID uint8
	// RemoteIA is the remote RemoteIA.
	RemoteIA addr.IA

	// Events is used by the Session to announce changes in health (i.e., remote gateway unreachable
	// or reachable). A Session starts in a Down state (for which no event is sent), and should
	// announce it is up when it is healthy.
	//
	// Run will return an error if Events is nil.
	Events chan<- SessionEvent

	// SessionMonitorEvents is the channel on each events from the session monitor arrive.
	// Close this channel to shut down the Session.
	//
	// Run will return an error if SessionMonitorEvents is nil.
	SessionMonitorEvents <-chan SessionEvent

	// PathMonitorRegistration is used to access paths from the path monitor.
	//
	// Run will return an error if Paths is nil.
	PathMonitorRegistration PathMonitorRegistration

	// PathMonitorPollInterval sets how often the path should be read from the
	// path monitor. Must be set.
	PathMonitorPollInterval time.Duration

	// DataplaneSession points to the data-plane session managed by this control-plane session.
	//
	// Run will return an error if DataplaneSession is nil.
	DataplaneSession DataplaneSession

	Metrics SessionMetrics

	// pathResultMtx protects access to pathResult.
	pathResultMtx sync.RWMutex
	// pathResult is the last result from pathhealth monitoring.
	pathResult pathhealth.Selection

	runCalledMutex sync.Mutex
	// runCalled is incremented on the first execution of Run. Future calls will return an error.
	runCalled bool
}

// Run starts the health checking for the remote gateway. It returns when the
// session terminates.
func (s *Session) Run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	if err := s.runCalledCheck(); err != nil {
		return err
	}

	if err := s.validate(); err != nil {
		return err
	}

	pathPoll := time.NewTicker(s.PathMonitorPollInterval)
	defer pathPoll.Stop()

	for {
		select {
		case sessionMonitorEvent, ok := <-s.SessionMonitorEvents:
			if !ok {
				return nil
			}
			logger.Debug("Received event from session monitor", "session_id", s.ID,
				"event", sessionMonitorEvent)
			s.Events <- sessionMonitorEvent
			logger.Debug("Sent event to control-plane router", "session_id", s.ID,
				"event", sessionMonitorEvent)

		case <-pathPoll.C:
			s.pathResultMtx.Lock()
			newPathResult := s.PathMonitorRegistration.Get()
			diff := pathSelectionDiff{old: s.pathResult, new: newPathResult}
			if s.Metrics.PathChanges != nil && diff.hasDiff() {
				metrics.CounterInc(s.Metrics.PathChanges)
			}
			if logger.Enabled(log.DebugLevel) && diff.hasDiff() {
				diff.log(logger)
			}
			s.pathResult = newPathResult
			if err := s.DataplaneSession.SetPaths(s.pathResult.Paths); err != nil {
				logger.Error("setting paths", "err", err)
			}
			s.pathResultMtx.Unlock()
		}
	}
}

func (s *Session) runCalledCheck() error {
	s.runCalledMutex.Lock()
	defer s.runCalledMutex.Unlock()

	if s.runCalled {
		return serrors.New("run called more than once")
	}
	s.runCalled = true
	return nil
}

func (s *Session) validate() error {
	if s.Events == nil {
		return serrors.New("events channel must not be nil")
	}
	if s.PathMonitorRegistration == nil {
		return serrors.New("path monitor registration must not be nil")
	}
	if s.SessionMonitorEvents == nil {
		return serrors.New("session monitor events channel must not be nil")
	}
	if s.DataplaneSession == nil {
		return serrors.New("dataplane session must not be nil")
	}
	if s.PathMonitorPollInterval == 0 {
		return serrors.New("path monitor interval must be set")
	}
	return nil
}

// sessionPaths list the path diagnostics for a session.
type sessionPaths struct {
	// ID the ID of the session.
	ID uint8
	// PathInfo the info from the last path result.
	PathInfo pathhealth.PathInfo
	// Paths the paths from the last path result.
	Paths []snet.Path
}

func (s *Session) sessionPaths() sessionPaths {
	s.pathResultMtx.RLock()
	defer s.pathResultMtx.RUnlock()

	return sessionPaths{
		ID:       s.ID,
		PathInfo: s.pathResult.PathInfo,
		Paths:    s.pathResult.Paths,
	}
}

type pathSelectionDiff struct {
	old pathhealth.Selection
	new pathhealth.Selection
}

func (d pathSelectionDiff) hasDiff() bool {
	if reflect.DeepEqual(d.old.PathInfo, d.new.PathInfo) {
		return false
	}
	if len(d.old.Paths) != len(d.new.Paths) {
		return true
	}
	for i, np := range d.new.Paths {
		op := d.old.Paths[i]
		if snet.Fingerprint(np).String() != snet.Fingerprint(op).String() {
			return true
		}
	}
	return false
}

func (d pathSelectionDiff) log(logger log.Logger) {
	if len(d.old.Paths) != len(d.new.Paths) {
		logger.Debug("Changing dataplane path",
			"reason", "different amount", "new_paths", d.new.Paths)
		return
	}
	logger.Debug("Changing dataplane path",
		"reason", "different fingerprints", "new_paths", d.new.Paths)
}
