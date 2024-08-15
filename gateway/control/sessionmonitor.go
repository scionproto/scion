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
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/gateway/pathhealth"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	gatewaypb "github.com/scionproto/scion/pkg/proto/gateway"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/worker"
)

const (
	defaultProbeInterval    = 500 * time.Millisecond
	defaultHealthExpiration = 2 * time.Second
)

// Event describes a health check event.
type Event int

// The different Event values.
const (
	EventDown Event = iota
	EventUp
)

// PathMonitorRegistration provides access to the paths.
type PathMonitorRegistration interface {
	Get() pathhealth.Selection
	Close()
}

// SessionMonitorMetrics contains the metrics for the session monitor.
type SessionMonitorMetrics struct {
	// Probes is the number of sent probes.
	Probes metrics.Counter
	// ProbeReplies is the number of probe replies received.
	ProbeReplies metrics.Counter
	// IsHealthy is a binary gauge showing a sessions healthiness.
	IsHealthy metrics.Gauge
	// StateChanges counts the number of state changes for this session.
	StateChanges metrics.Counter
}

// SessionMonitor monitors a session with a remote gateway instance.
type SessionMonitor struct {
	// ID is the ID of the session. It's used in the probe packet and for
	// diagnostics.
	ID uint8
	// RemoteIA is the remote RemoteIA the gateway to monitor is in.
	RemoteIA addr.IA
	// ProbeAddr is the probe address of the remote gateway instance.
	ProbeAddr *net.UDPAddr
	// Events is the channel where the monitor events are published to. Note
	// that an event is only published on change. The SessionMonitor will
	// close the events channel when it shuts down.
	Events chan<- SessionEvent
	// Paths is used to access paths from the path monitor.
	Paths PathMonitorRegistration
	// ProbeConn is the connection that is used to send and receive probe
	// packets.
	ProbeConn net.PacketConn
	// ProbeInterval is the interval at which the remote is probed. Can be left
	// zero and a default value will be used.
	ProbeInterval time.Duration
	// HealthExpiration is the duration after the last successful probe after
	// which a remote is considered unhealthy.
	HealthExpiration time.Duration
	// Metrics are the metrics which are modified during the operation of the
	// monitor. If empty no metrics are reported.
	Metrics SessionMonitorMetrics

	// stateMtx protects the state from concurrent access.
	stateMtx sync.RWMutex
	// state is the current state the monitor is in.
	state Event
	// expirationTimer is used to trigger expiration.
	expirationTimer *time.Timer
	// receivedProbe indicates a probe was received.
	receivedProbe chan struct{}

	// rawProbe is the raw probe to send.
	rawProbe []byte

	workerBase worker.Base
}

func (m *SessionMonitor) initDefaults() {
	if m.ProbeInterval == 0 {
		m.ProbeInterval = defaultProbeInterval
	}
	if m.HealthExpiration == 0 {
		m.HealthExpiration = defaultHealthExpiration
	}
}

// Run runs the session monitor. It blocks until Close is called..
func (m *SessionMonitor) Run(ctx context.Context) error {
	return m.workerBase.RunWrapper(ctx, m.setupInternalState, m.run)
}

func (m *SessionMonitor) run(ctx context.Context) error {
	defer close(m.Events)
	defer m.expirationTimer.Stop()
	go func() {
		defer log.HandlePanic()
		m.drainConn(ctx)
	}()
	probeTicker := time.NewTicker(m.ProbeInterval)
	defer probeTicker.Stop()
	m.sendProbe(ctx)
	for {
		select {
		case <-probeTicker.C:
			m.sendProbe(ctx)
		case <-m.receivedProbe:
			m.handleProbeReply(ctx)
		case <-m.expirationTimer.C:
			select {
			case <-m.receivedProbe:
				m.handleProbeReply(ctx)
			default:
				m.handleExpiration(ctx)
			}
		case <-m.workerBase.GetDoneChan():
			return nil
		}
	}
}

func (m *SessionMonitor) notification(e Event) SessionEvent {
	return SessionEvent{SessionID: m.ID, Event: m.state}
}

// Close stops the session monitor.
func (m *SessionMonitor) Close(ctx context.Context) error {
	return m.workerBase.CloseWrapper(ctx, nil)
}

// sessionState is for diagnostics and indicates the healthiness of a session.
type sessionState struct {
	// ID is the ID of the session.
	ID uint8
	// Healthy indicates whether this session receveived probes recently and is
	// thus seen as healthy.
	Healthy bool
}

func (m *SessionMonitor) sessionState() sessionState {
	m.stateMtx.RLock()
	defer m.stateMtx.RUnlock()
	return sessionState{
		ID:      m.ID,
		Healthy: m.state == EventUp,
	}
}

func (m *SessionMonitor) setupInternalState(ctx context.Context) error {
	m.initDefaults()
	m.state = EventDown
	probe := &gatewaypb.ControlRequest{
		Request: &gatewaypb.ControlRequest_Probe{
			Probe: &gatewaypb.ProbeRequest{
				SessionId: uint32(m.ID),
			},
		},
	}
	raw, err := proto.Marshal(probe)
	if err != nil {
		return serrors.Wrap("marshaling probe", err)
	}
	m.rawProbe = raw
	m.receivedProbe = make(chan struct{})
	m.expirationTimer = time.NewTimer(m.HealthExpiration)
	return nil
}

func (m *SessionMonitor) sendProbe(ctx context.Context) {
	logger := log.FromCtx(ctx)
	paths := m.Paths.Get().Paths
	if len(paths) == 0 {
		// no path nothing we can do.
		logger.Debug("No path for session monitoring", "session_id", m.ID)
		return
	}
	remote := &snet.UDPAddr{
		IA:      m.RemoteIA,
		Host:    m.ProbeAddr,
		NextHop: paths[0].UnderlayNextHop(),
		Path:    paths[0].Dataplane(),
	}
	// TODO(sustrik): This should not block. Use SetWriteDeadline.
	// Do so when creating the connection.
	_, err := m.ProbeConn.WriteTo(m.rawProbe, remote)
	if err != nil {
		logger.Error("Error sending probe", "err", err)
		return
	}
	metrics.CounterInc(m.Metrics.Probes)
}

func (m *SessionMonitor) handleProbeReply(ctx context.Context) {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	logger := log.FromCtx(ctx)
	if m.state != EventUp {
		m.state = EventUp

		select {
		case <-m.workerBase.GetDoneChan():
		case m.Events <- m.notification(m.state):
			metrics.GaugeSet(m.Metrics.IsHealthy, 1)
			metrics.CounterInc(m.Metrics.StateChanges)
			logger.Debug("Sent UP event", "session_id", m.ID)
		}
	}
	// proper reset sequence (https://pkg.go.dev/time#Timer.Reset)
	if !m.expirationTimer.Stop() {
		// The channel could be empty if we were previously in the down state
		// and now received a new reply. The important bit is that the channel
		// is drained.
		select {
		case <-m.expirationTimer.C:
		default:
		}

	}
	m.expirationTimer.Reset(m.HealthExpiration)
}

func (m *SessionMonitor) handleExpiration(ctx context.Context) {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	logger := log.FromCtx(ctx)
	// ignore if the state is already down.
	if m.state == EventDown {
		return
	}
	m.state = EventDown

	select {
	case <-m.workerBase.GetDoneChan():
	case m.Events <- m.notification(m.state):
		metrics.GaugeSet(m.Metrics.IsHealthy, 0)
		metrics.CounterInc(m.Metrics.StateChanges)
		logger.Debug("Sent DOWN event", "session_id", m.ID)
	}
}

func (m *SessionMonitor) drainConn(ctx context.Context) {
	logger := log.FromCtx(ctx)
	buf := make([]byte, common.SupportedMTU)
	for {
		n, _, err := m.ProbeConn.ReadFrom(buf)
		// XXX(karampok): The .ReadFrom(buf) is a blocking action and when
		// gracefully close the SessionMonitor it unblocks because the ProbeConn
		// closed. In that there is an error which we can ignore.
		select {
		case <-m.workerBase.GetDoneChan():
			return
		default:
		}
		if err != nil {
			logger.Error("Reading from probe conn", "err", err)
			continue
		}
		if err := m.handlePkt(buf[:n]); err != nil {
			logger.Error("Handling probe reply", "err", err)
		}
	}
}

func (m *SessionMonitor) handlePkt(raw []byte) error {
	var ctrl gatewaypb.ControlResponse
	if err := proto.Unmarshal(raw, &ctrl); err != nil {
		return serrors.Wrap("parsing control response", err)
	}
	probe, ok := ctrl.Response.(*gatewaypb.ControlResponse_Probe)
	if !ok {
		return serrors.New("unexpected control response", "type", common.TypeOf(ctrl.Response))
	}
	if probe.Probe.SessionId != uint32(m.ID) {
		return serrors.New("unexpected session ID in response",
			"response_id", probe.Probe.SessionId, "expected_id", m.ID)
	}
	metrics.CounterInc(m.Metrics.ProbeReplies)
	m.receivedProbe <- struct{}{}
	return nil
}
