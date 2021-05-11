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
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/worker"
)

// SessionEvent is used by the session to inform other components of
// changes to health.
type SessionEvent struct {
	// SessionID contains the ID of the session announcing the event.
	SessionID uint8
	// Event signals whether the Session went up or down.
	Event Event
}

// RoutingTable is the dataplane routing table as seen from the control plane.
type RoutingTable interface {
	// Activate will signal the routing table object that it is active.
	Activate()
	// Deactivate will signal the routing table object that is not active. This
	// call will clean up resources that are not needed anymore, e.g. exported
	// routes.
	Deactivate()
	RoutingTableReader
	RoutingTableWriter
}

// RoutingTableReader contains the read operations of a data-plane routing table.
type RoutingTableReader interface {
	RouteIPv4(pkt layers.IPv4) PktWriter
	RouteIPv6(pkt layers.IPv6) PktWriter
}

// RoutingTableWriter contains the write operations of a data-plane routing table.
type RoutingTableWriter interface {
	// SetSession sets the session for the routing table index. It replaces an
	// existing session if there is already one for this index. The method
	// returns an error if the index is not known. If session is nil the method
	// returns an error.
	SetSession(index int, session PktWriter) error
	// ClearSession removes any session for the given index. If there is no
	// session for the given index it is a no-op. The method returns an
	// error if the index is not known.
	ClearSession(index int) error
}

// Router contains is a session-health-aware routing table builder that manages
// the data-plane routing table.
type Router struct {
	// RoutingTable is the dataplane routing table.
	RoutingTable RoutingTableWriter
	// RoutingTableIndices maps a routing table index to a priority-ordered list
	// of session ids.
	RoutingTableIndices map[int][]uint8
	// DataplaneSessions are the dataplane sessions.
	DataplaneSessions map[uint8]PktWriter
	// Events is the channel that session events are read from. Note that
	// session IDs sent in this channel must be associated with a session in the
	// session groups.
	Events <-chan SessionEvent
	// Logger is the logger to use. If nil no logs are written.
	Logger log.Logger

	// stateMtx protects mutable state.
	stateMtx sync.RWMutex
	// sessionStates indicates the state of a session.
	sessionStates map[uint8]Event
	// currentSessions maps routing table indices to the session in use.
	currentSessions map[int]uint8

	workerBase worker.Base
}

// Run informs the router to start reading events from its event channel and
// push updates to the data-plane router. It returns when the router terminates.
func (r *Router) Run() error {
	log.SafeDebug(r.Logger, "Router starting")
	return r.workerBase.RunWrapper(r.initData, r.run)
}

func (r *Router) run() error {
	for {
		select {
		case <-r.workerBase.GetDoneChan():
			return nil
		case event := <-r.Events:
			log.SafeDebug(r.Logger, "Control-plane router received event", "event", event)
			err := r.handleEvent(event)
			if err != nil && r.Logger != nil {
				r.Logger.Error("Handling event", "err", err)
			}
		}
	}
}

// Close stops all internal goroutines.
func (r *Router) Close() error {
	return r.workerBase.CloseWrapper(nil)
}

func (r *Router) initData() error {
	r.currentSessions = make(map[int]uint8, len(r.RoutingTableIndices))
	r.sessionStates = make(map[uint8]Event, len(r.DataplaneSessions))
	return nil
}

func (r *Router) handleEvent(event SessionEvent) error {
	r.stateMtx.Lock()
	defer r.stateMtx.Unlock()
	// sanity check that the session exists. If it doesn't all other map lookups
	// would fail.
	_, ok := r.DataplaneSessions[event.SessionID]
	if !ok {
		return serrors.New("event for unknown session", "id", event.SessionID)
	}
	var errors serrors.List
	r.sessionStates[event.SessionID] = event.Event
	switch event.Event {
	case EventUp:
		getIdx := func(ids []uint8, search uint8) int {
			for i, id := range ids {
				if id == search {
					return i
				}
			}
			return -1
		}
		for rtID, sessIDs := range r.RoutingTableIndices {
			// Skip routing table indices that do not contain the session this
			// event is for.
			if getIdx(sessIDs, event.SessionID) == -1 {
				continue
			}
			// check if there is already a session for this index.
			currentID, ok := r.currentSessions[rtID]
			if !ok {
				err := r.RoutingTable.SetSession(rtID, r.DataplaneSessions[event.SessionID])
				if err != nil {
					// if the routing table doesn't know the index it means
					// something was wrongly programmed.
					panic(serrors.WrapStr("adding to routing table", err, "id", rtID))
				}
				r.currentSessions[rtID] = event.SessionID
				continue
			}
			bestID, idx := r.findSession(rtID)
			if idx == -1 {
				panic("no index found but session went up.")
			}
			if currentID == bestID {
				continue
			}
			err := r.RoutingTable.SetSession(rtID, r.DataplaneSessions[bestID])
			if err != nil {
				// if the routing table doesn't know the index it means
				// something was wrongly programmed.
				panic(serrors.WrapStr("adding to routing table", err, "id", rtID))
			}
			r.currentSessions[rtID] = bestID
		}
	case EventDown:
		// session going down.
		for rtID, sessID := range r.currentSessions {
			if sessID != event.SessionID {
				continue
			}
			// it's the current session find a new one.
			newID, idx := r.findSession(rtID)
			if idx == -1 {
				if err := r.RoutingTable.ClearSession(rtID); err != nil {
					// if the routing table doesn't know the index it means
					// something was wrongly programmed.
					panic(serrors.WrapStr("deleting from routing table", err, "id", rtID))
				}
				delete(r.currentSessions, rtID)
			} else {
				if err := r.RoutingTable.SetSession(rtID, r.DataplaneSessions[newID]); err != nil {
					// if the routing table doesn't know the index it means
					// something was wrongly programmed.
					panic(serrors.WrapStr("adding to routing table", err, "id", rtID))
				}
				r.currentSessions[rtID] = newID
			}
		}
	default:
		return serrors.New("unknown", "event", event.Event)
	}
	return errors.ToError()
}

// findSession finds the first session that is up for the routing table ID. The
// second return value is the index, it's -1 if no session that is up is found.
func (r *Router) findSession(rtID int) (uint8, int) {
	for i, sessID := range r.RoutingTableIndices[rtID] {
		if r.sessionStates[sessID] == EventUp {
			return sessID, i
		}
	}
	return 0, -1
}

// DiagnosticsWrite writes diagnostics for the router to the writer.
func (r *Router) DiagnosticsWrite(w io.Writer) {
	r.stateMtx.RLock()
	defer r.stateMtx.RUnlock()

	type Diagnostics struct {
		RoutingTableIndices map[int][]uint8
		CurrentSessions     map[int]uint8
		SessionStates       map[uint8]Event
	}
	d := Diagnostics{
		RoutingTableIndices: r.RoutingTableIndices,
		CurrentSessions:     r.currentSessions,
		SessionStates:       r.sessionStates,
	}
	raw, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error collecting Router diagnostics %v", err)))
		return
	}
	w.Write(raw)
	w.Write([]byte("\n"))
}
