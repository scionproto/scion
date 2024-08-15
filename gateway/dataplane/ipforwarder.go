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
	"context"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
)

var decodeOptions = gopacket.DecodeOptions{
	NoCopy: true,
	Lazy:   true,
}

// IPForwarderMetrics is used by the forwarder to report information about internal operation.
type IPForwarderMetrics struct {
	// IPPktBytesLocalRecv counts the IP packet bytes received from the local network. If nil, the
	// metric is not reported.
	IPPktBytesLocalRecv metrics.Counter
	// IPPktsLocalRecv counts the number of IP packets received from the local network. If nil,
	// the metric is not reported.
	IPPktsLocalRecv metrics.Counter
	// IPPktsNoRoute counts the number of IP packets received from the local network and that were
	// discarded because no routing entry was found. If nil, the metric is not reported.
	IPPktsNoRoute metrics.Counter
	// IPPktInvalidPackets counts the number of packet parsing errors. If nil, the metric
	// is not reported.
	IPPktsInvalid metrics.Counter
	//  IPPktsFragmented the number of fragmented packet. If nil, the metric is not reported.
	IPPktsFragmented metrics.Counter
	// ReceiveLocalErrors counts the number of read errors encountered on the raw packets source.
	// If nil, the metric is not reported.
	ReceiveLocalErrors metrics.Counter
}

// IPForwarder reads packets from the reader, routes them according to a routing table and
// dispatches them to a session.
type IPForwarder struct {
	// Reader is the source of raw packets. It must not be nil.
	//
	// Each read should yield a whole packet.
	Reader io.Reader
	// RoutingTable is used to decide where packets should be sent. It must not be nil.
	RoutingTable control.RoutingTableReader
	// Metrics is used by the forwarder to report information about internal operation.
	// If a metric is not initialized, it is not reported.
	Metrics IPForwarderMetrics
}

// Run forwards packets from the reader based on the routing table.
func (f *IPForwarder) Run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	if err := f.validate(); err != nil {
		return err
	}
	f.initMetrics()
	for {
		// FIXME(scrye): This allocates memory for each forwarded packet (as it was done in the old
		// gateway). It should take them from a buffer pool.
		buf := make([]byte, common.MaxMTU)

		length, err := f.Reader.Read(buf)
		if err != nil {
			metrics.CounterInc(f.Metrics.ReceiveLocalErrors)
			return serrors.Wrap("read device error", err)
		}
		metrics.CounterInc(f.Metrics.IPPktsLocalRecv)
		metrics.CounterAdd(f.Metrics.IPPktBytesLocalRecv, float64(length))
		if length == 0 {
			metrics.CounterInc(f.Metrics.IPPktsInvalid)
			logger.Debug("forwarder: read 0 length packet")
			continue
		}

		var packet gopacket.Packet
		switch version := int(buf[0] >> 4); version {
		case 4:
			packet = gopacket.NewPacket(buf[:length], layers.LayerTypeIPv4, decodeOptions)
		case 6:
			packet = gopacket.NewPacket(buf[:length], layers.LayerTypeIPv6, decodeOptions)
		default:
			metrics.CounterInc(f.Metrics.IPPktsInvalid)
			logger.Debug("forwarder: unknown IP version", "version", version)
			continue
		}

		if packet.ErrorLayer() != nil {
			metrics.CounterInc(f.Metrics.IPPktsInvalid)
			logger.Debug("forwarder: failed to parse packet",
				"err", packet.ErrorLayer().Error())
			continue
		}

		var session control.PktWriter
		switch ip := packet.NetworkLayer().(type) {
		case *layers.IPv4:
			if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
				metrics.CounterInc(f.Metrics.IPPktsFragmented)
				logger.Debug("forwarder: ignored fragmented packet")
				continue
			}
			session = f.RoutingTable.RouteIPv4(*ip)
		case *layers.IPv6:
			session = f.RoutingTable.RouteIPv6(*ip)
		}

		if session == nil {
			metrics.CounterInc(f.Metrics.IPPktsNoRoute)
			continue
		}

		session.Write(packet)
	}
}

func (f *IPForwarder) validate() error {
	if f.Reader == nil {
		return serrors.New("packet reader must not be nil")
	}
	if f.RoutingTable == nil {
		return serrors.New("routing table must not be nil")
	}
	return nil
}

func (f *IPForwarder) initMetrics() {
	if f.Metrics.IPPktsInvalid != nil {
		f.Metrics.IPPktsInvalid.Add(0)
	}
	if f.Metrics.ReceiveLocalErrors != nil {
		f.Metrics.ReceiveLocalErrors.Add(0)
	}
}
