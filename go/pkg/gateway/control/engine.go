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
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth/policies"
	"github.com/scionproto/scion/go/pkg/worker"
)

const (
	// sessionEventsLength is the size of the channel connecting sessions to the
	// control-plane routing table.
	sessionEventsLength = 10
)

// Engine contains an entire routing context for the current control-plane configuration.
// It constructs channels between components, starts session goroutines,
// and runs the router.
type Engine struct {
	// SessionConfigs contains the configurations of sessions that are part of the context.
	SessionConfigs []*SessionConfig

	// RoutingTable contains the routing object that updates should be pushed to.
	RoutingTable RoutingTable

	// RoutingTableIndices maps routing table indices to the list of eligible
	// sessions, sorted by priority.
	RoutingTableIndices map[int][]uint8

	// PathMonitor is used to construct registrations for path discovery.
	// Run will return an error if the PathMonitor is nil.
	PathMonitor PathMonitor

	// ProbeConnFactory constructs connections to be used for sending and receiving probe packets.
	// Run will return an error if ProbeConnFactory is nil.
	ProbeConnFactory PacketConnFactory

	// DataplaneSessionFactory is used to construct dataplane sessions.
	DataplaneSessionFactory DataplaneSessionFactory

	// Logger to be passed down to worker goroutines. If nil, logging is disabled.
	Logger log.Logger

	// Metrics are the metrics which are modified during the operation of the engine.
	// If empty, no metrics are reported.
	Metrics EngineMetrics

	// stateMtx protects the state below from concurrent access.
	stateMtx sync.RWMutex
	// eventNotifications is the channel that connects control-plane sessions to the
	// control-plane router. Sessions will write to this channel, while the router will
	// read events from it.
	eventNotifications chan SessionEvent
	// dataplaneSessions contains the constructed dataplane sessions.
	dataplaneSessions map[uint8]DataplaneSession
	// sessionMonitors contains the goroutines for session monitoring.
	sessionMonitors []*SessionMonitor
	// sessions contains the goroutines for control-plane sessions.
	sessions []*Session
	// router contains the goroutine for the control-plane router.
	router *Router
	// pathMonitorRegistrations are registrations constructed by the engine for path
	// retrieval in sessions.
	pathMonitorRegistrations []PathMonitorRegistration
	// probeConns are local connections used to send probes.
	probeConns []net.PacketConn

	workerBase worker.Base
}

// Run constructs the necessary channels, starts session goroutines and runs the router.
// It returns when the context terminates.
func (e *Engine) Run() error {
	log.SafeDebug(e.Logger, "Engine starting")
	return e.workerBase.RunWrapper(e.setup, e.run)
}

// DiagnosticsWrite writes diagnostics to the writer.
func (e *Engine) DiagnosticsWrite(w io.Writer) {
	e.stateMtx.RLock()
	defer e.stateMtx.RUnlock()
	type engineDiagnostics struct {
		SessionStates []sessionState
		SessionPaths  []sessionPaths
	}
	d := engineDiagnostics{
		SessionStates: make([]sessionState, 0, len(e.sessionMonitors)),
		SessionPaths:  make([]sessionPaths, 0, len(e.sessions)),
	}
	for _, sm := range e.sessionMonitors {
		d.SessionStates = append(d.SessionStates, sm.sessionState())
	}
	for _, s := range e.sessions {
		d.SessionPaths = append(d.SessionPaths, s.sessionPaths())
	}
	raw, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error collecting Engine diagnostics %v", err)))
		return
	}
	w.Write(raw)
	w.Write([]byte("\n"))

	w.Write([]byte("Last seen session configs:\n"))
	raw, err = json.MarshalIndent(e.SessionConfigs, "", "    ")
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error collecting Engine SessionConfigs diagnostics %v", err)))
		return
	}
	w.Write(raw)
	w.Write([]byte("\n"))

	w.Write([]byte("Control-plane routing table:\n"))
	e.router.DiagnosticsWrite(w)
	w.Write([]byte("\n"))

	if dw, ok := e.RoutingTable.(DiagnosticsWriter); ok {
		w.Write([]byte("Data-plane routing table:\n"))
		dw.DiagnosticsWrite(w)
		w.Write([]byte("\n"))
	}
}

// Status prints the status page to the writer.
func (e *Engine) Status(w io.Writer) {
	e.stateMtx.RLock()
	defer e.stateMtx.RUnlock()

	type session struct {
		ID       uint8
		PolicyID int

		ProbeAddr *net.UDPAddr
		Healthy   bool
		PathInfo  string
	}
	sessions := make(map[addr.IA]map[uint8]*session)
	for _, sm := range e.sessionMonitors {
		iaSessions, ok := sessions[sm.RemoteIA]
		if !ok {
			iaSessions = make(map[uint8]*session)
			sessions[sm.RemoteIA] = iaSessions
		}
		iaSessions[sm.ID] = &session{
			ID:        sm.ID,
			ProbeAddr: sm.ProbeAddr,
			Healthy:   sm.sessionState().Healthy,
		}
	}
	for _, s := range e.sessions {
		iaSessions, ok := sessions[s.RemoteIA]
		if !ok {
			// should never be nil, but better be safe here.
			iaSessions = make(map[uint8]*session)
			sessions[s.RemoteIA] = iaSessions
		}
		entry := iaSessions[s.ID]
		if entry == nil {
			// should never be nil, but better be safe here.
			entry = &session{ID: s.ID}
			iaSessions[s.ID] = entry
		}
		entry.PathInfo = s.pathResult.Info
	}
	for _, sc := range e.SessionConfigs {
		iaSessions, ok := sessions[sc.IA]
		if !ok {
			// should never be nil, but better be safe here.
			iaSessions = make(map[uint8]*session)
			sessions[sc.IA] = iaSessions
		}
		entry := iaSessions[sc.ID]
		if entry == nil {
			// should never be nil, but better be safe here.
			entry = &session{ID: sc.ID}
			iaSessions[sc.ID] = entry
		}
		entry.PolicyID = sc.PolicyID
	}
	sortedIAs := make([]addr.IA, 0, len(sessions))
	for ia := range sessions {
		sortedIAs = append(sortedIAs, ia)
	}
	sort.Slice(sortedIAs, func(i, j int) bool {
		return sortedIAs[i].IAInt() < sortedIAs[j].IAInt()
	})
	printSessions := func(m map[uint8]*session) {
		iaSessions := make([]*session, 0, len(m))
		for _, s := range m {
			iaSessions = append(iaSessions, s)
		}
		sort.Slice(iaSessions, func(i, j int) bool { return iaSessions[i].ID < iaSessions[j].ID })
		for _, s := range iaSessions {
			lines := []string{
				fmt.Sprintf("  SESSION %d, POLICY_ID %d, REMOTE: %s, HEALTHY %t",
					s.ID, s.PolicyID, s.ProbeAddr, s.Healthy),
				"    PATHS:",
				s.PathInfo,
			}
			w.Write([]byte(strings.Join(lines, "\n")))
			w.Write([]byte("\n"))
		}
	}
	for _, ia := range sortedIAs {
		w.Write([]byte(fmt.Sprintf("ISD-AS %s\n", ia)))
		printSessions(sessions[ia])
		w.Write([]byte("\n"))
	}

	if dw, ok := e.RoutingTable.(DiagnosticsWriter); ok {
		w.Write([]byte("\nROUTING TABLE:\n"))
		dw.DiagnosticsWrite(w)
	}
}

func (e *Engine) setup() error {
	if err := e.validate(); err != nil {
		return err
	}
	return e.initWorkers()
}

func (e *Engine) run() error {
	log.SafeDebug(e.Logger, "Engine worker setup finished")
	// Wait for the channel to be closed before returning. This is to ensure that the worker
	// doesn't return from Run until it has shut down.
	<-e.workerBase.GetDoneChan()
	return nil
}

func (e *Engine) validate() error {
	if e.RoutingTable == nil {
		return serrors.New("routing table must not be nil")
	}
	if e.PathMonitor == nil {
		return serrors.New("path monitor must not be nil")
	}
	if e.ProbeConnFactory == nil {
		return serrors.New("probe connection factory must not be nil")
	}
	if e.DataplaneSessionFactory == nil {
		return serrors.New("dataplane session factory must not be nil")
	}
	return nil
}

func (e *Engine) initWorkers() error {
	e.stateMtx.Lock()
	defer e.stateMtx.Unlock()

	numSessions := len(e.SessionConfigs)

	e.eventNotifications = make(chan SessionEvent, sessionEventsLength)
	e.dataplaneSessions = make(map[uint8]DataplaneSession)
	e.sessions = make([]*Session, 0, numSessions)
	e.sessionMonitors = make([]*SessionMonitor, 0, numSessions)
	e.pathMonitorRegistrations = make([]PathMonitorRegistration, 0, numSessions)

	for _, config := range e.SessionConfigs {
		dataplaneSession := e.DataplaneSessionFactory.New(config.ID, config.PolicyID,
			config.IA, config.Gateway.Data)
		remoteIA := config.IA
		pathMonitorRegistration := e.PathMonitor.Register(remoteIA, &policies.Policies{
			PathPolicy: config.PathPolicy,
			PerfPolicy: config.PerfPolicy,
			PathCount:  config.PathCount,
		}, config.PolicyID)
		probeConn, err := e.ProbeConnFactory.New()
		if err != nil {
			return err
		}

		sessionMonitorEvents := make(chan SessionEvent, 1)
		labels := []string{
			"remote_isd_as", remoteIA.String(),
			"policy_id", strconv.Itoa(config.PolicyID),
			"session_id", strconv.Itoa(int(config.ID)),
		}

		sessionMonitor := &SessionMonitor{
			ID:        config.ID,
			RemoteIA:  remoteIA,
			ProbeAddr: config.Gateway.Probe,
			Events:    sessionMonitorEvents,
			Paths:     pathMonitorRegistration,
			ProbeConn: probeConn,
			Metrics: SessionMonitorMetrics{
				Probes: metrics.CounterWith(
					e.Metrics.SessionMonitorMetrics.Probes, labels...),
				ProbeReplies: metrics.CounterWith(
					e.Metrics.SessionMonitorMetrics.ProbeReplies, labels...),
				IsHealthy: metrics.GaugeWith(
					e.Metrics.SessionMonitorMetrics.IsHealthy, labels...),
			},
			Logger: e.Logger,
		}
		e.workerBase.WG.Add(1)
		go func() {
			defer log.HandlePanic()
			defer e.workerBase.WG.Done()
			if err := sessionMonitor.Run(); err != nil {
				panic(err) // application can't recover from this
			}
		}()

		session := &Session{
			ID:                      config.ID,
			RemoteIA:                remoteIA,
			Events:                  e.eventNotifications,
			SessionMonitorEvents:    sessionMonitorEvents,
			PathMonitorRegistration: pathMonitorRegistration,
			PathMonitorPollInterval: 250 * time.Millisecond,
			DataplaneSession:        dataplaneSession,
			Logger:                  e.Logger,
		}
		e.workerBase.WG.Add(1)
		go func() {
			defer log.HandlePanic()
			defer e.workerBase.WG.Done()
			if err := session.Run(); err != nil {
				panic(err) // application can't recover from an error here
			}
		}()

		e.dataplaneSessions[config.ID] = dataplaneSession
		e.sessions = append(e.sessions, session)
		e.sessionMonitors = append(e.sessionMonitors, sessionMonitor)
		e.pathMonitorRegistrations = append(e.pathMonitorRegistrations, pathMonitorRegistration)
		e.probeConns = append(e.probeConns, probeConn)
	}
	// XXX(shitz): We have to explicitly create a map of PktWriters, since Go's typesystem doesn't
	// allow us to pass in a map of DataplaneSessions.
	writers := make(map[uint8]PktWriter)
	for k, v := range e.dataplaneSessions {
		writers[k] = v
	}
	e.router = &Router{
		RoutingTable:        e.RoutingTable,
		RoutingTableIndices: e.RoutingTableIndices,
		DataplaneSessions:   writers,
		Events:              e.eventNotifications,
		Logger:              e.Logger,
	}
	e.workerBase.WG.Add(1)
	go func() {
		defer log.HandlePanic()
		defer e.workerBase.WG.Done()
		if err := e.router.Run(); err != nil {
			panic(err) // application can't recover from an error here
		}
	}()

	return nil
}

// Close stops all internal goroutines and waits for them to finish.
func (e *Engine) Close() error {
	return e.workerBase.CloseWrapper(e.close)
}

func (e *Engine) close() error {
	for i, conf := range e.SessionConfigs {
		if err := e.sessionMonitors[i].Close(); err != nil {
			panic(err) // application can't recover from an error here
		}
		// control-plane sessions shut down automatically after session monitors close their
		// event channels
		e.dataplaneSessions[conf.ID].Close()
	}
	if e.router != nil {
		if err := e.router.Close(); err != nil {
			panic(err) // application can't recover from an error here
		}
	}
	e.workerBase.WG.Wait()
	// All goroutines have finished, we can destroy all resources.
	for i := range e.SessionConfigs {
		e.pathMonitorRegistrations[i].Close()
		if err := e.probeConns[i].Close(); err != nil {
			panic(err) // application can't recover from an error here
		}
	}
	return nil
}

// EngineMetrics aggregates the metrics used by various control-plane engine components.
type EngineMetrics struct {
	SessionMonitorMetrics SessionMonitorMetrics
}

// PacketConnFactory is used to construct net.PacketConn objects for control-plane communication.
type PacketConnFactory interface {
	New() (net.PacketConn, error)
}

// RoutingTableSwapper is a concurrency-safe setter for a routing table's entire state.
type RoutingTableSwapper interface {
	SetRoutingTable(RoutingTable)
}

// PktWriter is the interface exposed by a data-plane session for forwarding packets.
type PktWriter interface {
	Write(packet gopacket.Packet)
}

// DataplaneSessionFactory is used to construct a data-plane session with a specific ID towards a
// remote.
type DataplaneSessionFactory interface {
	New(sessID uint8, policyID int, remoteIA addr.IA, remoteAddr net.Addr) DataplaneSession
}

// PathMonitor is used to construct registrations for path discovery.
type PathMonitor interface {
	Register(ia addr.IA, policies *policies.Policies, policyID int) PathMonitorRegistration
}
