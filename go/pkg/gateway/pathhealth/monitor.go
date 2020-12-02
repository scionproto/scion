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

// Package pathhealth monitors paths to different ASes. Call Monitor.Register()
// to start monitoring paths to a remote AS using a chosen path policy. The call
// returns a registration object which can be used to obtain the best path.
package pathhealth

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// defaultPathUpdateInterval specifies how often the paths are retrieved from the daemon.
	defaultPathUpdateInterval = 10 * time.Second
	// defaultProbeInterval specifies how often should path probes be sent.
	defaultProbeInterval = 500 * time.Millisecond
)

// RemoteWatcher watches multiple paths to a given remote.
type RemoteWatcher interface {
	// UpdatePaths gets new paths from the SCION daemon. This method may block.
	UpdatePaths(snet.Router)
	// SendProbes sends probes on all the monitored paths.
	SendProbes(conn snet.PacketConn, localAddr snet.SCIONAddress)
	// HandleProbeReply handles a single probe reply packet.
	HandleProbeReply(id, seq uint16)
	// Cleanup stops monitoring paths that are not being used anymore.
	Cleanup()
	// Watchers returns a list of all active PathWatchers
	Watchers() []PathWatcher
}

// RemoteWatcherFactory creates RemoteWatchers.
type RemoteWatcherFactory interface {
	New(remote addr.IA) RemoteWatcher
}

// RevocationStore keeps track of revocations.
type RevocationStore interface {
	// AddRevocation adds a revocation.
	AddRevocation(rev *path_mgmt.RevInfo)
	// IsRevoked returns true if there is at least one revoked interface on the path.
	IsRevoked(path snet.Path) bool
	// Cleanup removes all expired revocations.
	Cleanup()
}

// Monitor monitors paths to a set of remote ASes.
type Monitor struct {
	// LocalIA is the ID of the local AS.
	LocalIA addr.IA
	// LocalIP is the IP address of the local host.
	LocalIP net.IP
	// Conn is the underlying conn for sending probes
	Conn net.PacketConn
	// RevocationHandler is the revocation handler.
	RevocationHandler snet.RevocationHandler
	// Router is the path manager connected to the SCION daemon.
	Router snet.Router
	// PathUpdateInterval specified how often the paths are retrieved from the daemon.
	PathUpdateInterval time.Duration
	// Probeinterval defines the interval at which probes are sent. If it is not
	// set a default is used.
	ProbeInterval time.Duration
	// RevocationStore keeps track of the revocations.
	RevocationStore RevocationStore
	// RemoteWatcherFactory creates a RemoteWatcher for the specified remote.
	RemoteWatcherFactory RemoteWatcherFactory
	// Logger is the logger. If nil, nothing is logged.
	Logger log.Logger

	// conn is the snet connection used to exchange the probes.
	conn snet.PacketConn
	// stopChannel transports stop signal to the worker goroutine.
	stopChannel chan struct{}

	mutex sync.Mutex
	// remoteWatchers is a map of all monitored IAs.
	remoteWatchers map[addr.IA]*remoteWatcherItem
	pktChan        <-chan traceroutePkt
}

// Run starts the monitor and blocks until Close is called.
func (m *Monitor) Run() {
	if m.stopChannel != nil {
		panic("monitor must only be started once")
	}

	if m.PathUpdateInterval == 0 {
		m.PathUpdateInterval = defaultPathUpdateInterval
	}
	if m.ProbeInterval == 0 {
		m.ProbeInterval = defaultProbeInterval
	}
	m.stopChannel = make(chan struct{})
	m.remoteWatchers = make(map[addr.IA]*remoteWatcherItem)
	pktChan := make(chan traceroutePkt, 10)
	m.pktChan = pktChan
	m.conn = snet.NewSCIONPacketConn(m.Conn,
		scmpHandler{
			wrappedHandler: snet.DefaultSCMPHandler{RevocationHandler: m.RevocationHandler},
			pkts:           pktChan,
		},
		true,
	)

	log.SafeInfo(m.Logger, "Started PathMonitor")
	go func() {
		defer log.HandlePanic()
		m.handleProbeReplies()
	}()
	go func() {
		defer log.HandlePanic()
		m.drainConn()
	}()
	m.run()
}

// Register starts monitoring given AS under the specified selector.
func (m *Monitor) Register(remote addr.IA, selector PathSelector) *Registration {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// If a monitor for the given AS does not exist, create it.
	// Otherwise, increase its reference count.
	remoteWatcher := m.remoteWatchers[remote]
	if remoteWatcher == nil {
		remoteWatcher = &remoteWatcherItem{
			RemoteWatcher: m.RemoteWatcherFactory.New(remote),
			refCount:      1,
		}
		m.remoteWatchers[remote] = remoteWatcher
		remoteWatcher.UpdatePaths(m.Router)
	} else {
		remoteWatcher.refCount++
	}
	return &Registration{
		monitor:       m,
		remoteWatcher: remoteWatcher,
		pathSelector:  selector,
	}
}

// Close stops the path monitor.
func (m *Monitor) Close() {
	close(m.stopChannel)
}

func (m *Monitor) unregister(remoteWatcher *remoteWatcherItem) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// If the monitor for the IA is not needed any more, remove it.
	remoteWatcher.refCount--
	if remoteWatcher.refCount == 0 {
		delete(m.remoteWatchers, remoteWatcher.remote)
	}
}

// run triggers periodical tasks on the pathmonitor.
func (m *Monitor) run() {
	pathUpdateTicker := time.NewTicker(m.PathUpdateInterval)
	probeTicker := time.NewTicker(m.ProbeInterval)
	defer probeTicker.Stop()
	defer m.conn.Close() // This kills the handleProbeReply goroutine.
	defer log.SafeInfo(m.Logger, "Terminated PathMonitor")

	m.updatePaths()
	for {
		select {
		case <-pathUpdateTicker.C:
			m.updatePaths()
		case <-probeTicker.C:
			m.cleanup()
			m.sendProbes()
		case <-m.stopChannel:
			return
		}
	}
}

// updatePaths gets new set of paths from SCION daemon.
func (m *Monitor) updatePaths() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, remoteWatcher := range m.remoteWatchers {
		remoteWatcher.UpdatePaths(m.Router)
	}
}

// sendProbes sends probes through all the monitored paths.
func (m *Monitor) sendProbes() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	localAddr := snet.SCIONAddress{IA: m.LocalIA, Host: addr.HostFromIP(m.LocalIP)}
	for _, remoteWatcher := range m.remoteWatchers {
		remoteWatcher.SendProbes(m.conn, localAddr)
	}
}

// cleanup deletes all unused paths from monitoring as well as all expired revocations.
func (m *Monitor) cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, remoteWatcher := range m.remoteWatchers {
		remoteWatcher.Cleanup()
	}
	m.RevocationStore.Cleanup()
}

func (m *Monitor) drainConn() {
	closing := func() bool {
		select {
		case <-m.stopChannel:
			return true
		default:
			return false
		}
	}

	for {
		var pkt snet.Packet
		var ov net.UDPAddr

		err := m.conn.ReadFrom(&pkt, &ov)
		// This avoids logging errors for closing connections.
		if closing() {
			return
		}
		if errors.Is(err, io.EOF) {
			// dispatcher is currently down so back off.
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err != nil {
			opErr, ok := err.(*snet.OpError)
			if ok {
				m.handleRevocation(opErr.RevInfo())
				continue
			}
			log.SafeInfo(m.Logger, "Unexpected error when reading probe replies", "err", err)
		}
	}
}

// handleProbeReplies reads incoming probe replies and dispatches them as needed.
func (m *Monitor) handleProbeReplies() {
	for {
		select {
		case pkt := <-m.pktChan:
			m.handleProbeReply(pkt)
		case <-m.stopChannel:
			return
		}
	}
}

// handleRevocation deals with a received revocation
func (m *Monitor) handleRevocation(rev *path_mgmt.RevInfo) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.RevocationStore.AddRevocation(rev)
}

// handleProbeReply dispatches a single probe reply packet.
func (m *Monitor) handleProbeReply(pkt traceroutePkt) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	remoteWatcher := m.remoteWatchers[pkt.Remote]
	if remoteWatcher == nil {
		log.SafeDebug(m.Logger, "Unsolicited reply (ISD-AS no longer monitored)",
			"remote", pkt.Remote)
		// Reply from an IA that is no longer monitored.
		return
	}
	remoteWatcher.HandleProbeReply(pkt.Identifier, pkt.Sequence)
}

// remoteWatcherItem is a helper structure that augments RemoteWatcher with
// Monitor specific metadata.
type remoteWatcherItem struct {
	RemoteWatcher
	remote addr.IA
	// refCount keeps track of how many references to this object there are.
	refCount int
}
