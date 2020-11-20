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

package dataplane

import (
	"fmt"
	"net"
	"sync"

	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/snet"
)

type PathStatsPublisher interface {
	PublishEgressStats(fingerprint string, frames int64, bytes int64)
}

// SessionMetrics report traffic and error counters for a session. They must be instantiated with
// the labels "remote_isd_as" and "policy_id".
type SessionMetrics struct {
	// IPPktsSent is the IP packets count sent.
	IPPktsSent metrics.Counter
	// IPPktBytesSent is the IP packet bytes sent.
	IPPktBytesSent metrics.Counter
	// FramesSent is the frames count sent.
	FramesSent metrics.Counter
	// FrameBytesSent is the frame bytes sent.
	FrameBytesSent metrics.Counter
	// SendExternalError is the error count when sending frames to the external network.
	SendExternalErrors metrics.Counter
}

type Session struct {
	SessionID          uint8
	GatewayAddr        net.UDPAddr
	DataPlaneConn      net.PacketConn
	PathStatsPublisher PathStatsPublisher
	Metrics            SessionMetrics

	mutex sync.Mutex
	// sender is the currently used sender. If there's no available path, it is nil.
	sender *sender
	// path is the path used by current sender.
	path snet.Path
}

// Close signals that the session should close up its internal Connections. Close returns as
// soon as forwarding goroutines are signaled to shut down (never blocks).
func (s *Session) Close() {
	if s.sender != nil {
		s.sender.Close()
	}
}

// Write encodes the packet and sends it to the network.
// The packet may be silently dropped.
func (s *Session) Write(pkt []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.sender == nil {
		return
	}
	s.sender.Write(pkt)
}

func (s *Session) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return fmt.Sprintf("{ID: %d, path: %s}", s.SessionID, s.path)
}

// SetPath sets the path for subsequent packets encapsulated by the session.
// Packets that were written up to this point will still be sent via the old
// path. There are two reasons for that:
//
// 1. New path may have smaller MTU causing the already buffered frame not to
// fit in.
//
// 2. Paths can have different latencies, meaning that switching to new path
// could cause packets to be delivered out of order. Using new sender with new stream
// ID causes creation of new reassemby queue on the remote side, thus avoiding the
// reordering issues.
func (s *Session) SetPath(path snet.Path) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// If path hasn't changed do nothing.
	if pathsEqual(s.path, path) {
		return nil
	}
	s.path = path
	// Close the old connection. (Buffered frames will still be sent out.)
	if s.sender != nil {
		s.sender.Close()
		s.sender = nil
	}
	// If there's no path do nothing. Packets will be silently dropped.
	if path == nil {
		return nil
	}
	var err error
	s.sender, err = newSender(s.SessionID, s.DataPlaneConn, s.path, s.GatewayAddr,
		s.PathStatsPublisher, s.Metrics)
	if err != nil {
		return err
	}
	return nil
}

func pathsEqual(x, y snet.Path) bool {
	if x == nil && y == nil {
		return true
	}
	if x == nil || y == nil {
		return false
	}
	return snet.Fingerprint(x) == snet.Fingerprint(y) &&
		x.Metadata() != nil && y.Metadata() != nil &&
		x.Metadata().MTU == y.Metadata().MTU &&
		x.Metadata().Expiry.Equal(y.Metadata().Expiry)
}
