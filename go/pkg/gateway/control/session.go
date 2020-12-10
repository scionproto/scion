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
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
)

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

	// PathMonitorPollInterval sets how often the path should be read from the path monitor.
	// If 0, the path monitor is only queried when the session monitor reports a state
	// change to up.
	PathMonitorPollInterval time.Duration

	// DataplaneSession points to the data-plane session managed by this control-plane session.
	//
	// Run will return an error if DataplaneSession is nil.
	DataplaneSession DataplaneSession

	// Logger is the logger to use. If nil no logs are written.
	Logger log.Logger

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
func (s *Session) Run() error {
	if err := s.runCalledCheck(); err != nil {
		return err
	}

	if err := s.validate(); err != nil {
		return err
	}

	// pathChan stays nil and never drains if no poll interval is set
	var pathChan <-chan time.Time
	if s.PathMonitorPollInterval != 0 {
		ticker := time.NewTicker(s.PathMonitorPollInterval)
		defer ticker.Stop()
		pathChan = ticker.C
	}

	for {
		select {
		case sessionMonitorEvent, ok := <-s.SessionMonitorEvents:
			if !ok {
				return nil
			}
			log.SafeDebug(s.Logger, "Received event from session monitor", "session_id", s.ID,
				"event", sessionMonitorEvent)
			s.Events <- sessionMonitorEvent
			log.SafeDebug(s.Logger, "Sent event to control-plane router", "session_id", s.ID,
				"event", sessionMonitorEvent)

			if s.PathMonitorPollInterval == 0 && sessionMonitorEvent.Event == EventUp {
				s.pathResultMtx.Lock()
				s.pathResult = s.PathMonitorRegistration.Get()
				s.DataplaneSession.SetPaths(s.pathResult.Paths)
				s.pathResultMtx.Unlock()
			}
		case <-pathChan:
			s.pathResultMtx.Lock()
			s.pathResult = s.PathMonitorRegistration.Get()
			s.DataplaneSession.SetPaths(s.pathResult.Paths)
			s.pathResultMtx.Unlock()
		}
	}
}

func (s *Session) runCalledCheck() error {
	s.runCalledMutex.Lock()
	defer s.runCalledMutex.Unlock()

	if s.runCalled == true {
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
	return nil
}

// sessionPaths list the path diagnostics for a session.
type sessionPaths struct {
	// ID the ID of the session.
	ID uint8
	// Info the info from the last path result.
	Info string
	// Paths the paths from the last path result.
	Paths []snet.Path
}

func (s *Session) sessionPaths() sessionPaths {
	s.pathResultMtx.RLock()
	defer s.pathResultMtx.RUnlock()

	return sessionPaths{
		ID:    s.ID,
		Info:  s.pathResult.Info,
		Paths: s.pathResult.Paths,
	}
}
