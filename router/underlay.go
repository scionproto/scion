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
	"net/netip"

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
// link and underlay connection is a channel, on the sending side, and should be a demultiplexer on
// the receiving side. The demultiplexer must have a src-addr:link map in all cases where links
// share connections.
//
// Regardless of underlay, links come in three scopes: internal, sibling, and external. The
// difference in behaviour is hidden from the rest of the router. The router only needs to
// associate an interface ID with a link. If the interface ID belongs to a sibling router, then
// the link is a sibling link. If the interface ID is zero, then the link is the internal link.
type Link interface {
	IsUp() bool
	IfID() uint16
	Scope() LinkScope
	BFDSession() *bfd.Session
	Send(p *Packet) bool
	SendBlocking(p *Packet)
}

// A provider of connectivity over some underlay implementation
//
// For any given underlay, there are three kinds of Link implementations to choose from.
// The difference between them is the intent regarding addressing.
//
// TODO(multi_underlay): addresses are still explicitly IP/port. In the next step, we have to
// make them opaque; to be interpreted only by the underlay implementation.
type UnderlayProvider interface {

	// SetConnNewer is a unit testing device: it allows the replacement of the function
	// that creates new underlay connections. Underlay implementations can, at their
	// choice, implement this properly, or panic if it is called. The tests have to know
	// which it is. Only router/export_test invokes this directly.
	SetConnNewer(newer any)

	// NumConnections returns the current number of configured connections.
	NumConnections() int

	// Start puts the provider in the running state. In that state, the provider can deliver
	// incoming packets to its output channels and will send packets present on its input
	// channels. Only connection in existence at the time of calling Start() will be
	// started. Calling Start has no effect on already running connections.
	Start(ctx context.Context, pool chan *Packet, proQs []chan *Packet)

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
		metrics InterfaceMetrics,
	) (Link, error)

	// NewSinblingLink returns a link that addresses any number of remote ASes via a single sibling
	// router. So, it is not given an ifID at creation, but it is given a remote underlay address:
	// that of the sibling router. Outgoing packets do not need an underlay destination as metadata.
	// Incoming packets have no defined ingress ifID.
	NewSiblingLink(
		qSize int,
		bfd *bfd.Session,
		local string,
		remote string,
		metrics InterfaceMetrics,
	) (Link, error)

	// NewIternalLink returns a link that addresses any host internal to the enclosing AS, so it is
	// given neither ifID nor remote address. Outgoing packets need to have a destination address as
	// metadata. Incoming packets have no defined ingress ifID.
	NewInternalLink(localAddr netip.AddrPort, qSize int, metrics InterfaceMetrics) (Link, error)
}
