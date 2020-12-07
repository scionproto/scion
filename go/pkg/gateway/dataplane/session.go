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
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/serialx/hashring"

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
	// senders is a list of currently used senders.
	senders map[snet.PathFingerprint]senderEntry
	// hashRing is used to map packet quintuples to paths.
	hashRing *hashring.HashRing
}

type senderEntry struct {
	sender *sender
	path   snet.Path
}

// Close signals that the session should close up its internal Connections. Close returns as
// soon as forwarding goroutines are signaled to shut down (never blocks).
func (s *Session) Close() {
	for _, entry := range s.senders {
		entry.sender.Close()
	}
}

// Write encodes the packet and sends it to the network.
// The packet may be silently dropped.
func (s *Session) Write(packet gopacket.Packet) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.senders) == 0 {
		return
	}
	if len(s.senders) == 1 {
		// If there's only one path, we can skip the load balancing part.
		var entry senderEntry
		for _, entry = range s.senders {
			break
		}
		entry.sender.Write(packet.Data())
		return
	}
	// Choose the path based on the packet's quintuple.
	fingerprint, ok := s.hashRing.GetNode(string(extractQuintuple(packet)))
	if ok {
		s.senders[snet.PathFingerprint(fingerprint)].sender.Write(packet.Data())
	}

}

func (s *Session) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	res := fmt.Sprintf("ID: %d", s.SessionID)
	var keys []string
	for fingerprint := range s.senders {
		keys = append(keys, string(fingerprint))
	}
	sort.Strings(keys)
	for _, key := range keys {
		res += fmt.Sprintf("\n    %v", s.senders[snet.PathFingerprint(key)].path)
	}
	return res
}

// SetPaths sets the paths for subsequent packets encapsulated by the session.
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
func (s *Session) SetPaths(paths []snet.Path) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.senders == nil {
		s.senders = make(map[snet.PathFingerprint]senderEntry)
	}

	senders := make(map[snet.PathFingerprint]senderEntry)
	fingerprints := []string{}
	for _, path := range paths {
		fingerprint := snet.Fingerprint(path)
		fingerprints = append(fingerprints, string(fingerprint))
		oldSender, ok := s.senders[fingerprint]
		if ok && pathsEqual(path, oldSender.path) {
			senders[fingerprint] = oldSender
			delete(s.senders, fingerprint)
		} else {
			snd, err := newSender(s.SessionID, s.DataPlaneConn, path,
				s.GatewayAddr, s.PathStatsPublisher, s.Metrics)
			if err != nil {
				return err
			}
			senders[fingerprint] = senderEntry{
				sender: snd,
				path:   path,
			}
		}
	}
	for _, entry := range s.senders {
		entry.sender.Close()
	}
	s.senders = senders
	s.hashRing = hashring.New(fingerprints)
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

func extractQuintuple(packet gopacket.Packet) []byte {
	// Protocol number and addresses.
	var proto layers.IPProtocol
	var q []byte
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		q = []byte{byte(ip.Protocol)}
		q = append(q, ip.SrcIP...)
		q = append(q, ip.DstIP...)
		proto = ip.Protocol
	case *layers.IPv6:
		q = []byte{byte(ip.NextHeader)}
		q = append(q, ip.SrcIP...)
		q = append(q, ip.DstIP...)
		proto = ip.NextHeader
	default:
		panic(fmt.Sprintf("unexpected network layer %T", packet.NetworkLayer()))
	}
	// Ports.
	switch proto {
	case layers.IPProtocolTCP:
		pos := len(q)
		q = append(q, 0, 0, 0, 0)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		binary.BigEndian.PutUint16(q[pos:pos+2], uint16(tcp.SrcPort))
		binary.BigEndian.PutUint16(q[pos+2:pos+4], uint16(tcp.DstPort))
	case layers.IPProtocolUDP:
		pos := len(q)
		q = append(q, 0, 0, 0, 0)
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		binary.BigEndian.PutUint16(q[pos:pos+2], uint16(udp.SrcPort))
		binary.BigEndian.PutUint16(q[pos+2:pos+4], uint16(udp.DstPort))
	}
	return q
}
