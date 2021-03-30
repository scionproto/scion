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
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
)

// DefaultPathWatcherFactory creates PathWatchers.
type DefaultPathWatcherFactory struct {
	// Logger is the parent logger. If nil, the PathWatcher is constructed
	// without any logger.
	Logger log.Logger
}

// New creates a PathWatcher that monitors a specific path.
func (f *DefaultPathWatcherFactory) New(remote addr.IA, path snet.Path, id uint16) PathWatcher {
	logger := log.SafeNewLogger(
		f.Logger,
		"remote_isd_as", remote.String(),
		"path", fmt.Sprint(path),
	)
	log.SafeInfo(logger, "Path monitoring started")

	return &DefaultPathWatcher{
		remote: remote,
		id:     id,
		path:   path.Copy(),
		logger: logger,
	}
}

// DefaultPathWatcher monitors a single SCION path.
type DefaultPathWatcher struct {
	// remote is the ID of the AS being monitored.
	remote addr.IA
	// path is the monitored path.
	path snet.Path
	// id is the SCMP traceroute ID used by the dispatcher to route the SCMP
	// traceroute replies back to this instance of gateway. We want a different
	// ID for each PathWatcher instance, so that it can be used to distinguish
	// replies for different PathWatchers, even two consecutive PathWatchers
	// monitoring the same path.
	id uint16
	// nextSeq is the sequence number to use for the next probe.
	// Assuming 2 probes a second, this will wrap over in ~9hrs.
	nextSeq uint16
	logger  log.Logger

	pathState pathState
}

// UpdatePath changes a path to be monitored. While actual path, as in "sequence
// of SCION interfaces", must never change for a single PathWatcher object,
// some elements of the path structure (e.g. expiration) do change and should be
// updated accordingly.
func (pw *DefaultPathWatcher) UpdatePath(path snet.Path) {
	if snet.Fingerprint(pw.path) != snet.Fingerprint(path) {
		return
	}
	pw.path = path.Copy()
}

// SendProbe sends a probe along the monitored path.
func (pw *DefaultPathWatcher) SendProbe(conn snet.PacketConn, localAddr snet.SCIONAddress) {
	pkt, err := pw.createProbepacket(localAddr)
	if err != nil {
		log.SafeError(pw.logger, "Failed to create path probe packet", "err", err)
		return
	}
	err = conn.WriteTo(
		pkt,
		pw.path.UnderlayNextHop(),
	)
	if err != nil {
		// TODO(sustrik): Metric
		log.SafeError(pw.logger, "Failed to send path probe", "err", err)
		return
	}
	pw.pathState.sendProbe(time.Now())
	pw.nextSeq++
}

// HandleProbeReply dispatches a single probe reply packet.
func (pw *DefaultPathWatcher) HandleProbeReply(seq uint16) {
	pw.pathState.receiveProbe(time.Now())
}

// Path returns a fresh copy of the monitored path.
func (pw *DefaultPathWatcher) Path() snet.Path {
	return pw.path.Copy()
}

// State returns the state of the monitored path.
func (pw *DefaultPathWatcher) State() State {
	now := time.Now()
	meta := pw.path.Metadata()
	if meta != nil && meta.Expiry.Before(now) {
		return State{
			IsExpired: true,
		}
	}
	return State{
		IsAlive: pw.pathState.active(),
	}
}

// Close stops the PathWatcher.
func (pw *DefaultPathWatcher) Close() {
	log.SafeInfo(pw.logger, "Path monitoring stopped")
}

func (pw *DefaultPathWatcher) createProbepacket(localAddr snet.SCIONAddress) (*snet.Packet, error) {
	p := pw.Path()
	if p == nil || p.Path().IsEmpty() {
		return nil, serrors.New("empty path")
	}
	meta := p.Metadata()
	if meta != nil && meta.Expiry.Before(time.Now()) {
		return nil, serrors.New("expired path", "expiration", meta.Expiry)
	}
	sp := p.Path()
	decodedPath := scion.Decoded{}
	if err := decodedPath.DecodeFromBytes(sp.Raw); err != nil {
		return nil, serrors.WrapStr("decoding path", err)
	}
	if len(decodedPath.InfoFields) > 0 {
		infoF := decodedPath.InfoFields[len(decodedPath.InfoFields)-1]
		if infoF.ConsDir {
			decodedPath.HopFields[len(decodedPath.HopFields)-1].IngressRouterAlert = true
		} else {
			decodedPath.HopFields[len(decodedPath.HopFields)-1].EgressRouterAlert = true
		}
	}
	decodedPath.SerializeTo(sp.Raw)
	return &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA: pw.remote,
				// The host doesn't really matter because it's terminated at the router.
				Host: addr.SvcNone,
			},
			Source: localAddr,
			Path:   sp,
			Payload: snet.SCMPTracerouteRequest{
				Identifier: pw.id,
				Sequence:   pw.nextSeq,
			},
		},
	}, nil
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
