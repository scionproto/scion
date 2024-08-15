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

package pathhealth

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	metrics2 "github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

const (
	// defaultProbeInterval specifies how often should path probes be sent.
	defaultProbeInterval = 500 * time.Millisecond
)

// DefaultPathWatcherFactory creates PathWatchers.
type DefaultPathWatcherFactory struct {
	// LocalIA is the ID of the local AS.
	LocalIA addr.IA
	// Topology is the helper class to get control-plane information for the
	// local AS.
	Topology snet.Topology
	// LocalIP is the IP address of the local host.
	LocalIP netip.Addr
	// RevocationHandler is the revocation handler.
	RevocationHandler snet.RevocationHandler
	// Probeinterval defines the interval at which probes are sent. If it is not
	// set a default is used.
	ProbeInterval time.Duration
	// ProbesSent keeps track of how many path probes have been sent per remote
	// AS.
	ProbesSent func(remote addr.IA) metrics.Counter
	// ProbesReceived keeps track of how many path probes have been received per
	// remote AS.
	ProbesReceived func(remote addr.IA) metrics.Counter
	// ProbesSendErrors keeps track of how many time sending probes failed per
	// remote.
	ProbesSendErrors func(remote addr.IA) metrics.Counter

	SCMPErrors             metrics2.Counter
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
}

// New creates a PathWatcher that monitors a specific path.
func (f *DefaultPathWatcherFactory) New(
	ctx context.Context,
	remote addr.IA,
	path snet.Path,
) (PathWatcher, error) {

	pktChan := make(chan traceroutePkt, 10)
	createCounter := func(
		create func(addr.IA) metrics.Counter, remote addr.IA,
	) metrics.Counter {
		if create == nil {
			return nil
		}
		return create(remote)
	}
	conn, err := (&snet.SCIONNetwork{
		SCMPHandler: scmpHandler{
			wrappedHandler: snet.DefaultSCMPHandler{
				RevocationHandler: f.RevocationHandler,
				SCMPErrors:        f.SCMPErrors,
			},
			pkts: pktChan,
		},
		PacketConnMetrics: f.SCIONPacketConnMetrics,
		Topology:          f.Topology,
	}).OpenRaw(ctx, &net.UDPAddr{IP: f.LocalIP.AsSlice()})
	if err != nil {
		return nil, serrors.Wrap("creating connection for probing", err)
	}
	return &pathWatcher{
		remote:        remote,
		probeInterval: f.ProbeInterval,
		conn:          conn,
		id:            uint16(conn.LocalAddr().(*net.UDPAddr).Port),
		localAddr: snet.SCIONAddress{
			IA:   f.LocalIA,
			Host: addr.HostIP(f.LocalIP),
		},
		pktChan:          pktChan,
		probesSent:       createCounter(f.ProbesSent, remote),
		probesReceived:   createCounter(f.ProbesReceived, remote),
		probesSendErrors: createCounter(f.ProbesSendErrors, remote),
		path:             createPathWrap(path),
	}, nil
}

type pathWatcher struct {
	// remote is the ID of the AS being monitored.
	remote addr.IA
	// probeInterval defines the interval at which probes are sent. If it is not
	// set a default is used.
	probeInterval time.Duration
	// conn is the packet conn used to send probes on. The pathwatcher takes
	// ownership and will close it on termination.
	conn snet.PacketConn
	// id is used as SCMP traceroute ID. Since each pathwatcher should have it's
	// own high port this value can be random.
	id uint16
	// localAddr is the local address used in the probe packet.
	localAddr snet.SCIONAddress
	// pktChan is the channel which provides the incoming packets on the
	// connection.
	pktChan <-chan traceroutePkt

	probesSent       metrics.Counter
	probesReceived   metrics.Counter
	probesSendErrors metrics.Counter

	// nextSeq is the sequence number to use for the next probe.
	// Assuming 2 probes a second, this will wrap over in ~9hrs.
	nextSeq   uint16
	pathState pathState
	pathMtx   sync.RWMutex
	path      pathWrap
	// packet is the snet packet used to send probes. It is re-used so that we
	// don't allocate a fresh one (and a buffer internally) for every send.
	packet *snet.Packet
}

func (w *pathWatcher) Run(ctx context.Context) {
	w.initDefaults()
	ctx, logger := log.WithLabels(
		ctx,
		"debug_id", log.NewDebugID().String(),
		"id", w.id,
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer wg.Done()

		w.drainConn(ctx)
	}()

	logger.Info("Starting path watcher", "path", fmt.Sprint(w.path.Path))
	defer logger.Info("Stopped path watcher")

	probeTicker := time.NewTicker(w.probeInterval)
	defer probeTicker.Stop()
	for {
		select {
		case <-w.pktChan:
			metrics.CounterInc(w.probesReceived)
			w.pathState.receiveProbe(time.Now())
		case <-probeTicker.C:
			w.sendProbe(ctx)
		case <-ctx.Done():
			// signal termination to connection drainer and then wait for it to
			// finish
			w.conn.Close()
			wg.Wait()
			return
		}
	}
}

func (w *pathWatcher) UpdatePath(path snet.Path) {
	w.pathMtx.Lock()
	defer w.pathMtx.Unlock()

	if w.path.fingerprint != snet.Fingerprint(path) {
		log.Error("UpdatePath with new fingerprint is invalid (BUG)",
			"current_path", fmt.Sprint(w.path.Path),
			"current_fingerprint", w.path.fingerprint,
			"new_path", fmt.Sprint(path),
			"new_fingerprint", snet.Fingerprint(path),
		)
		return
	}
	w.path = createPathWrap(path)
}

func (w *pathWatcher) Path() snet.Path {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()

	return w.path.Path
}

func (w *pathWatcher) State() State {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()

	now := time.Now()
	expiry := w.path.expiry
	if w.path.err == nil && expiry.Before(now) {
		return State{
			IsExpired: true,
		}
	}
	return State{
		IsAlive: w.pathState.active(),
	}
}

func (w *pathWatcher) initDefaults() {
	w.probeInterval = defaultProbeInterval
	w.packet = &snet.Packet{}
}

func (w *pathWatcher) drainConn(ctx context.Context) {
	logger := log.FromCtx(ctx)
	var pkt snet.Packet
	var ov net.UDPAddr
	for {
		err := w.conn.ReadFrom(&pkt, &ov)
		// This avoids logging errors for closing connections.
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if _, ok := err.(*snet.OpError); ok {
				// ignore SCMP errors they are already dealt with in the SCMP
				// handler.
				continue
			}
			logger.Info("Unexpected error when reading probe reply", "err", err)
		}
	}
}

func (w *pathWatcher) sendProbe(ctx context.Context) {
	w.pathMtx.RLock()
	defer w.pathMtx.RUnlock()

	w.pathState.sendProbe(time.Now())
	w.nextSeq++
	metrics.CounterInc(w.probesSent)
	logger := log.FromCtx(ctx)
	if err := w.prepareProbePacket(); err != nil {
		metrics.CounterInc(w.probesSendErrors)
		logger.Info("Failed to create path probe packet", "err", err)
		return
	}
	if err := w.conn.WriteTo(w.packet, w.path.UnderlayNextHop()); err != nil {
		metrics.CounterInc(w.probesSendErrors)
		logger.Error("Failed to send path probe", "err", err)
	}
}

func (w *pathWatcher) prepareProbePacket() error {
	if err := w.path.err; err != nil {
		return err
	}
	if w.path.expiry.Before(time.Now()) {
		return serrors.New("expired path", "expiration", w.path.expiry)
	}
	w.packet.PacketInfo = snet.PacketInfo{
		Destination: snet.SCIONAddress{
			IA: w.remote,
			// The host doesn't really matter because it's terminated at the router.
			Host: addr.HostSVC(addr.SvcNone),
		},
		Source: w.localAddr,
		Path:   w.path.dpPath,
		Payload: snet.SCMPTracerouteRequest{
			Identifier: w.id,
			Sequence:   w.nextSeq,
		},
	}
	return nil
}

type pathState struct {
	mu                sync.Mutex
	consecutiveProbes int
	lastReceived      time.Time
}

func (s *pathState) sendProbe(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Probe timed out.
	if s.lastReceived.Add(defaultProbeInterval * 2).Before(now) {
		s.consecutiveProbes = 0
		return
	}
}

func (s *pathState) receiveProbe(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReceived = now
	if s.consecutiveProbes < 3 {
		s.consecutiveProbes++
	}
}

func (s *pathState) active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consecutiveProbes == 3
}

// pathWrap is the monitored pathWrap it already contains a few precalculated values to
// prevent too much repeated work.
type pathWrap struct {
	// path is the monitored path.
	snet.Path
	fingerprint snet.PathFingerprint
	expiry      time.Time
	dpPath      snet.DataplanePath
	err         error
}

func createPathWrap(path snet.Path) pathWrap {
	p := pathWrap{
		Path:        path,
		fingerprint: snet.Fingerprint(path),
		expiry:      path.Metadata().Expiry,
	}

	original, ok := p.Dataplane().(snetpath.SCION)
	if !ok {
		p.err = serrors.New("not a scion path", "type", common.TypeOf(p.Dataplane()))
		return p
	}

	var decoded scion.Decoded
	if err := decoded.DecodeFromBytes(original.Raw); err != nil {
		p.err = serrors.Wrap("decoding path", err)
		return p
	}
	if len(decoded.InfoFields) > 0 {
		info := decoded.InfoFields[len(decoded.InfoFields)-1]
		if info.ConsDir {
			decoded.HopFields[len(decoded.HopFields)-1].IngressRouterAlert = true
		} else {
			decoded.HopFields[len(decoded.HopFields)-1].EgressRouterAlert = true
		}
	}

	alert, err := snetpath.NewSCIONFromDecoded(decoded)
	if err != nil {
		p.err = serrors.Wrap("serializing path", err)
		return p
	}
	p.dpPath = alert
	return p
}
