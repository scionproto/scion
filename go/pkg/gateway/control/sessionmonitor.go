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
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth"
	gatewaypb "github.com/scionproto/scion/go/pkg/proto/gateway"
	"github.com/scionproto/scion/go/pkg/worker"
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
}

func safeInc(counter metrics.Counter) {
	if counter != nil {
		counter.Add(1)
	}
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
	// Logger is the logger to use. If nil no logs are written.
	Logger log.Logger

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
func (m *SessionMonitor) Run() error {
	return m.workerBase.RunWrapper(m.setupInternalState, m.run)
}

func (m *SessionMonitor) run() error {
	defer close(m.Events)
	go func() {
		defer log.HandlePanic()
		m.drainConn()
	}()
	probeTicker := time.NewTicker(m.ProbeInterval)
	m.sendProbe()
	for {
		select {
		case <-probeTicker.C:
			m.sendProbe()
		case <-m.receivedProbe:
			m.handleProbeReply()
		case <-m.expirationTimer.C:
			m.handleExpiration()
		case <-m.workerBase.GetDoneChan():
			return nil
		}
	}
}

func (m *SessionMonitor) notification(e Event) SessionEvent {
	return SessionEvent{SessionID: m.ID, Event: m.state}
}

// Close stops the session monitor.
func (m *SessionMonitor) Close() error {
	return m.workerBase.CloseWrapper(nil)
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

func (m *SessionMonitor) setupInternalState() error {
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
		return serrors.WrapStr("marshaling probe", err)
	}
	m.rawProbe = raw
	m.receivedProbe = make(chan struct{})
	m.expirationTimer = time.NewTimer(m.HealthExpiration)
	return nil
}

func (m *SessionMonitor) sendProbe() {
	paths := m.Paths.Get().Paths
	if len(paths) == 0 {
		// no path nothing we can do.
		return
	}
	remote := &snet.UDPAddr{
		IA:      m.RemoteIA,
		Host:    m.ProbeAddr,
		NextHop: paths[0].UnderlayNextHop(),
		Path:    paths[0].Path(),
	}
	// TODO(sustrik): This should not block. Use SetWriteDeadline.
	// Do so when creating the connection.
	_, err := m.ProbeConn.WriteTo(m.rawProbe, remote)
	if err != nil {
		if m.Logger != nil {
			m.Logger.Error("Error sending probe", "err", err)
		}
		return
	}
	safeInc(m.Metrics.Probes)
}

func (m *SessionMonitor) handleProbeReply() {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	if m.state != EventUp {
		m.state = EventUp
		metrics.GaugeSet(m.Metrics.IsHealthy, 1)

		select {
		case <-m.workerBase.GetDoneChan():
		case m.Events <- m.notification(m.state):
			log.SafeDebug(m.Logger, "Sent UP event", "session_id", m.ID)
		}
	}
	m.expirationTimer.Reset(m.HealthExpiration)
}

func (m *SessionMonitor) handleExpiration() {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	// ignore if the state is already down.
	if m.state == EventDown {
		return
	}

	m.state = EventDown
	metrics.GaugeSet(m.Metrics.IsHealthy, 0)

	select {
	case <-m.workerBase.GetDoneChan():
	case m.Events <- m.notification(m.state):
		log.SafeDebug(m.Logger, "Sent DOWN event", "session_id", m.ID)
	}
}

func (m *SessionMonitor) drainConn() {
	buf := make([]byte, common.MaxMTU)
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
			log.SafeError(m.Logger, "Reading from probe conn", "err", err)
			continue
		}
		if err := m.handlePkt(buf[:n]); err != nil {
			log.SafeError(m.Logger, "Handling probe reply", "err", err)
		}
	}
}

func (m *SessionMonitor) handlePkt(raw []byte) error {
	var ctrl gatewaypb.ControlResponse
	if err := proto.Unmarshal(raw, &ctrl); err != nil {
		return serrors.WrapStr("parsing control response", err)
	}
	probe, ok := ctrl.Response.(*gatewaypb.ControlResponse_Probe)
	if !ok {
		return serrors.New("unexpected control response", "type", common.TypeOf(ctrl.Response))
	}
	if probe.Probe.SessionId != uint32(m.ID) {
		return serrors.New("unexpected session ID in response",
			"response_id", probe.Probe.SessionId, "expected_id", m.ID)
	}
	safeInc(m.Metrics.ProbeReplies)
	m.receivedProbe <- struct{}{}
	return nil
}
