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
	"github.com/olekukonko/tablewriter"

	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/worker"
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

	// DeviceManager is used to construct tunnel devices needed for forwarding and/or routing.
	DeviceManager DeviceManager

	// DataplaneSessionFactory is used to construct dataplane sessions.
	DataplaneSessionFactory DataplaneSessionFactory

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
	// deviceHandles contains references to tun devices currently used by data-plane sessions.
	deviceHandles []DeviceHandle
	// probeConns are local connections used to send probes.
	probeConns []net.PacketConn

	workerBase worker.Base
}

// Run sets up the gateway engine and starts all necessary goroutines.
// It returns when the setup is done.
func (e *Engine) Run(ctx context.Context) error {
	log.FromCtx(ctx).Debug("Engine starting")
	return e.workerBase.RunWrapper(ctx, e.setup, nil)
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
		fmt.Fprintf(w, "Error collecting Engine diagnostics %v", err)
		return
	}
	_, _ = w.Write(raw)
	fmt.Fprint(w, "\n")

	fmt.Fprint(w, "Last seen session configs:\n")
	raw, err = json.MarshalIndent(e.SessionConfigs, "", "    ")
	if err != nil {
		fmt.Fprintf(w, "Error collecting Engine SessionConfigs diagnostics %v", err)
		return
	}
	_, _ = w.Write(raw)
	fmt.Fprint(w, "\n")

	fmt.Fprint(w, "Control-plane routing table:\n")
	e.router.DiagnosticsWrite(w)
	fmt.Fprint(w, "\n")

	if dw, ok := e.RoutingTable.(DiagnosticsWriter); ok {
		fmt.Fprint(w, "Data-plane routing table:\n")
		dw.DiagnosticsWrite(w)
		fmt.Fprint(w, "\n")
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
		PathInfo  pathhealth.PathInfo
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
		entry.PathInfo = s.pathResult.PathInfo
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
		return sortedIAs[i] < sortedIAs[j]
	})
	printSessions := func(m map[uint8]*session) {
		iaSessions := make([]*session, 0, len(m))
		for _, s := range m {
			iaSessions = append(iaSessions, s)
		}
		sort.Slice(iaSessions, func(i, j int) bool { return iaSessions[i].ID < iaSessions[j].ID })
		for _, s := range iaSessions {
			fmt.Fprintf(w, "  SESSION %d, POLICY_ID %d, REMOTE: %s, HEALTHY %t\n",
				s.ID, s.PolicyID, s.ProbeAddr, s.Healthy)
			fmt.Fprint(w, "    PATHS:\n")
			renderPathInfo(s.PathInfo, w, 2)
			fmt.Fprint(w, "\n")
		}
	}
	for _, ia := range sortedIAs {
		fmt.Fprintf(w, "ISD-AS %s\n", ia)
		printSessions(sessions[ia])
		fmt.Fprint(w, "\n")
	}

	if dw, ok := e.RoutingTable.(DiagnosticsWriter); ok {
		fmt.Fprint(w, "\nROUTING TABLE:\n")
		dw.DiagnosticsWrite(w)
	}
}

func renderPathInfo(p pathhealth.PathInfo, w io.Writer, indent int) {
	var paths [][]string
	for _, path := range p {
		state := ""
		if path.Current {
			state = "-->"
		}
		if !path.Rejected {
			paths = append(paths, []string{
				strings.Repeat(" ", indent),
				state,
				fmt.Sprintf("%v", path.Revoked),
				path.Path,
			})
		} else {
			paths = append(paths, []string{
				strings.Repeat(" ", indent),
				path.RejectReason,
				"",
				path.Path,
			})
		}
	}
	table := tablewriter.NewWriter(w)
	table.SetAutoWrapText(false)
	table.SetBorder(false)
	table.SetHeaderLine(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeader([]string{"", "STATE", "REVOKED", "PATH"})
	table.AppendBulk(paths)
	table.Render()

}

func (e *Engine) setup(ctx context.Context) error {
	if err := e.validate(); err != nil {
		return err
	}
	return e.initWorkers(ctx)
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

func (e *Engine) initWorkers(ctx context.Context) error {
	e.stateMtx.Lock()
	defer e.stateMtx.Unlock()

	numSessions := len(e.SessionConfigs)

	e.eventNotifications = make(chan SessionEvent, sessionEventsLength)
	e.dataplaneSessions = make(map[uint8]DataplaneSession)
	e.sessions = make([]*Session, 0, numSessions)
	e.sessionMonitors = make([]*SessionMonitor, 0, numSessions)
	e.pathMonitorRegistrations = make([]PathMonitorRegistration, 0, numSessions)
	e.deviceHandles = make([]DeviceHandle, 0, numSessions)

	for _, config := range e.SessionConfigs {
		dataplaneSession := e.DataplaneSessionFactory.New(
			config.ID,
			config.PolicyID,
			config.IA,
			config.Gateway.Data,
		)
		remoteIA := config.IA
		pathMonitorRegistration := e.PathMonitor.Register(
			ctx,
			remoteIA,
			&policies.Policies{
				PathPolicy: config.PathPolicy,
				PerfPolicy: config.PerfPolicy,
				PathCount:  config.PathCount,
			},
			strconv.Itoa(config.PolicyID),
		)
		probeConn, err := e.ProbeConnFactory.New()
		if err != nil {
			return err
		}

		deviceHandle, err := e.DeviceManager.Get(ctx, remoteIA)
		if err != nil {
			return serrors.Wrap("getting tun device handle", err)
		}
		e.deviceHandles = append(e.deviceHandles, deviceHandle)

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
				StateChanges: metrics.CounterWith(
					e.Metrics.SessionMonitorMetrics.StateChanges, labels...),
			},
		}
		e.workerBase.WG.Add(1)
		go func() {
			defer log.HandlePanic()
			defer e.workerBase.WG.Done()
			if err := sessionMonitor.Run(ctx); err != nil {
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
			Metrics: SessionMetrics{
				metrics.CounterWith(e.Metrics.SessionMetrics.PathChanges, labels...),
			},
		}
		e.workerBase.WG.Add(1)
		go func() {
			defer log.HandlePanic()
			defer e.workerBase.WG.Done()
			if err := session.Run(ctx); err != nil {
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
		Metrics:             e.Metrics.RouterMetrics,
	}
	e.workerBase.WG.Add(1)
	go func() {
		defer log.HandlePanic()
		defer e.workerBase.WG.Done()
		if err := e.router.Run(ctx); err != nil {
			panic(err) // application can't recover from an error here
		}
	}()

	return nil
}

// Close stops all internal goroutines and waits for them to finish.
func (e *Engine) Close(ctx context.Context) error {
	return e.workerBase.CloseWrapper(ctx, e.close)
}

func (e *Engine) close(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	for i, conf := range e.SessionConfigs {
		if err := e.sessionMonitors[i].Close(ctx); err != nil {
			panic(err) // application can't recover from an error here
		}
		// control-plane sessions shut down automatically after session monitors close their
		// event channels
		e.dataplaneSessions[conf.ID].Close()
	}
	if e.router != nil {
		if err := e.router.Close(ctx); err != nil {
			panic(err) // application can't recover from an error here
		}
	}
	for i := range e.SessionConfigs {
		if err := e.deviceHandles[i].Close(); err != nil {
			// This can fail because an operator changed the device in some way. This means
			// the failure of some cleanup steps in Close is expected, so we log that something
			// unexpected happened but don't panic like in the other cases.
			logger.Info("Encountered error when closing device", "err", err)
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
	SessionMetrics        SessionMetrics
	SessionMonitorMetrics SessionMonitorMetrics
	RouterMetrics         RouterMetrics
}

// PacketConnFactory is used to construct net.PacketConn objects for control-plane communication.
type PacketConnFactory interface {
	New() (net.PacketConn, error)
}

// RoutingTableSwapper is a concurrency-safe setter for a routing table's entire state.
type RoutingTableSwapper interface {
	SetRoutingTable(RoutingTable) io.Closer
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
	Register(ctx context.Context, ia addr.IA, policies *policies.Policies,
		policyID string) PathMonitorRegistration
}
