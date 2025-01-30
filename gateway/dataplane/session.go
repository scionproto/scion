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
	"hash/crc64"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	crcTable = crc64.MakeTable(crc64.ECMA)
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
	senders []*sender
}

// Close signals that the session should close up its internal Connections. Close returns as
// soon as forwarding goroutines are signaled to shut down (never blocks).
func (s *Session) Close() {
	for _, snd := range s.senders {
		snd.Close()
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
		s.senders[0].Write(packet.Data())
		return
	}
	// Choose the path based on the packet's quintuple.
	hash := crc64.Checksum(extractQuintuple(packet), crcTable)
	index := hash % uint64(len(s.senders))
	s.senders[index].Write(packet.Data())
}

func (s *Session) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	res := fmt.Sprintf("ID: %d", s.SessionID)
	for _, snd := range s.senders {
		res += fmt.Sprintf("\n    %v", snd.path)
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

	created := make([]*sender, 0, len(paths))
	reused := make(map[*sender]bool, len(s.senders))
	for _, existingSender := range s.senders {
		reused[existingSender] = false
	}

	for _, path := range paths {
		// Find out whether we already have a sender for this path.
		// Keep using old senders whenever possible.
		if existingSender, ok := findSenderWithPath(s.senders, path); ok {
			reused[existingSender] = true
			continue
		}

		newSender, err := newSender(
			s.SessionID,
			s.DataPlaneConn,
			path,
			s.GatewayAddr,
			s.PathStatsPublisher,
			s.Metrics,
		)
		if err != nil {
			// Collect newly created senders to avoid go routine leak.
			for _, createdSender := range created {
				createdSender.Close()
			}
			return err
		}
		created = append(created, newSender)
	}

	newSenders := created
	for existingSender, reuse := range reused {
		if !reuse {
			existingSender.Close()
			continue
		}
		newSenders = append(newSenders, existingSender)
	}

	// Sort the paths to get a minimal amount of consistency,
	// at least in the case when new paths are the same as old paths.
	sort.Slice(newSenders, func(x, y int) bool {
		return strings.Compare(string(newSenders[x].pathFingerprint),
			string(newSenders[y].pathFingerprint)) == -1
	})
	s.senders = newSenders
	return nil
}

func findSenderWithPath(senders []*sender, path snet.Path) (*sender, bool) {
	for _, s := range senders {
		if pathsEqual(path, s.path) {
			return s, true
		}
	}
	return nil, false
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
