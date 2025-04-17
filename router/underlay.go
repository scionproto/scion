// Copyright 2025 SCION Association
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

// This module defines the interfaces between the router and the underlay network implementations.

package router

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/router/bfd"
)

// LinkScope describes the kind (or scope) of a link: internal, sibling, or external.
type LinkScope int

const (
	Internal LinkScope = iota // to/from end-hosts in the local AS
	Sibling                   // to/from (external interfaces owned by) a sibling router
	External                  // to/from routers in another AS
)

// Link embodies the router's idea of a point to point connection. A link associates the underlay
// connection with a BFDSession, a destination address, etc. It also allows the concrete send
// operation to be delegated to different underlay implementations. The association between
// link and underlay connection is a channel, on the sending side, and a demultiplexer on
// the receiving side. The demultiplexer must have a src-addr:link map in all cases where links
// share connections.
//
// Regardless of underlay, links come in three scopes: internal, sibling, and external. The
// difference in behaviour is hidden from the rest of the router. The router only needs to
// associate an interface ID with a link. If the interface ID belongs to a sibling router, then
// the link is a sibling link. If the interface ID is zero, then the link is the internal link.
//
// Note about Resolve. It resolves the given SCION host/svc address to an address on this underlay.
// This functionality is really only needed on the internal link,
type Link interface {
	// IsUp returns whether this link is functional according to the associated BFD session.
	IsUp() bool
	// IfID returns the interface ID associated with this link. 0 for sibling and internal links.
	IfID() uint16
	// Metrics returns the metrics specific to this link.
	Metrics() *InterfaceMetrics
	// Scope returns the scope of this link: internal, external, or sibling.
	Scope() LinkScope
	// BFDSession returns the BFD session associated with this link.
	BFDSession() *bfd.Session
	// Resolve finds and sets the packet's internal underlay destination for the given dst and port.
	Resolve(p *Packet, dst addr.Host, port uint16) error
	// Send queues the packet for sending over this link; discarding if the queue is full.
	Send(p *Packet) bool
	// SendBlocking queues the packet for sending over this link; blocking while the queue is full.
	SendBlocking(p *Packet)
}

// A provider of connectivity over some underlay implementation
//
// For any given underlay, there are three kinds of Link implementations to choose from.
// The difference between them is the intent regarding addressing.
//
// TODO(multi_underlay): The local internal address is explicitly a udpip underlay address as the
// main router code still assumes that the internal network underlay is always "udp/ip".
type UnderlayProvider interface {

	// SetConnOpener is a unit testing device: it allows the replacement of the function
	// that opens new underlay connections. Underlay implementations can, at their
	// choice, implement this properly, or panic if it is called. The opener can be anything
	// that suits the underlay implementation, so tests that use this must match the interface of
	// a specific underlay provider Opener.
	SetConnOpener(opener any)

	// NumConnections returns the current number of configured connections.
	NumConnections() int

	// Headroom returns the length of the largest header possibly added by this underlay.
	// The router core will ensure that all received packets are stored at an offset in the packet
	// buffer, such that the largest underlay header declared across all underlay providers can
	// be prepended to the SCION header without having to copy the packet or to allocate a separate
	// buffer.
	Headroom() int

	// SetDispatchPorts sets the range of auto-dispatched ports and default endhost port (the shim
	// dispatcher port). When translating a SCION port into an underlay port, any port between the
	// values of start and end remains unchanged, while any other will be replaced by the value of
	// redirect. Not all underlays have to provide that service and it might not be meaningful for a
	// non-ip underlay. In such cases, this method simply has no effect.
	SetDispatchPorts(start, end, redirect uint16)

	// AddSvc adds the address for the given service. This can be called multiple times per service.
	AddSvc(svc addr.SVC, host addr.Host, port uint16) error

	// DelSvc deletes the address for the given service.
	DelSvc(svc addr.SVC, host addr.Host, port uint16) error

	// Start puts the provider in the running state. In that state, the provider can deliver
	// incoming packets to its output channels and will send packets present on its input
	// channels. Only connection in existence at the time of calling Start() will be
	// started. Calling Start has no effect on already running connections.
	Start(ctx context.Context, pool PacketPool, proQs []chan *Packet)

	// Stop puts the provider in the stopped state. In that state, the provider no longer delivers
	// incoming packets and ignores packets present on its input channels. The provider is fully
	// stopped when this method returns. Only connections in existence at the time of calling Stop
	// will be stopped. Calling Stop() has no effect on already stopped connections.
	Stop()

	// NewExternalLink returns a link that addresses a single remote AS at a unique underlay
	// address. So, it is given an ifID and a underlay remote address at creation. Outgoing packets
	// do not need an underlay destination as metadata. Incoming packets have a defined ingress
	// ifID.
	NewExternalLink(
		qSize int,
		bfd *bfd.Session,
		local string,
		remote string,
		ifID uint16,
		metrics *InterfaceMetrics,
	) (Link, error)

	// NewSiblingLink returns a link that addresses any number of remote ASes via a single sibling
	// router. So, it is not given an ifID at creation, but it is given a remote underlay address:
	// that of the sibling router. Outgoing packets do not need an underlay destination as metadata.
	// Incoming packets have no defined ingress ifID.
	NewSiblingLink(
		qSize int,
		bfd *bfd.Session,
		local string,
		remote string,
		metrics *InterfaceMetrics,
	) (Link, error)

	// NewInternalLink returns a link that addresses any host internal to the enclosing AS, so it is
	// given neither ifID nor remote address. Outgoing packets need to have a destination address as
	// metadata. Incoming packets have no defined ingress ifID.
	NewInternalLink(localAddr string, qSize int, metrics *InterfaceMetrics) (Link, error)
}

// NewProviderFn is a function that instantiates an underlay provider.
type NewProviderFn func(batchSize, receiveBufferSize, sendBufferSize int) UnderlayProvider
