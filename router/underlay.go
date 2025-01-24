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
	"net/netip"
)

// LinkScope describes the kind (or scope) of a link: internal, sibling, or external.
type LinkScope int

const (
	Internal LinkScope = iota // to/from end-hosts in the local AS
	Sibling                   // to/from (external interfaces owned by) a sibling router
	External                  // to/from routers in another AS
)

// Link embodies the router's idea of a point to point connection. A link associates the underlay
// connection, with a bfdSession, a destination address, etc. It also allows the concrete send
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
	GetScope() LinkScope
	GetBfdSession() BfdSession
	IsUp() bool
	GetIfID() uint16
	GetRemote() netip.AddrPort // incremental refactoring: using code will move to underlay.
	Send(p *Packet) bool
	BlockSend(p *Packet)
}

// A provider of connectivity over some underlay implementation
//
// For any given underlay, there are three kinds of Link implementations to choose from.
// The difference between them is the intent regarding addressing.
//
// Incremental refactoring: addresses are still explicitly IP/port. In the next step, we have to
// make them opaque; to be interpreted only by the underlay implementation.
type UnderlayProvider interface {

	// NewExternalLink returns a link that addresses a single remote AS at a unique underlay
	// address. So, it is given an ifID and a underlay remote address at creation. Outgoing packets
	// do not need an underlay destination as metadata. Incoming packets have a defined ingress
	// ifID.
	NewExternalLink(
		conn BatchConn, qSize int, bfd BfdSession, remote netip.AddrPort, ifID uint16,
	) Link

	// NewSinblingLink returns a link that addresses any number of remote ASes via a single sibling
	// router. So, it is not given an ifID at creation, but it is given a remote underlay address:
	// that of the sibling router. Outgoing packets do not need an underlay destination as metadata.
	// Incoming packets have no defined ingress ifID.
	NewSiblingLink(qSize int, bfd BfdSession, remote netip.AddrPort) Link

	// NewIternalLink returns a link that addresses any host internal to the enclosing AS, so it is
	// given neither ifID nor address. Outgoing packets need to have a destination address as
	// metadata. Incoming packets have no defined ingress ifID.
	NewInternalLink(conn BatchConn, qSize int) Link

	// GetConnections returns the set of configured distinct connections in the provider.
	//
	// Incremental refactoring: this exists so most of the receiving code can stay in the main
	// dataplane code for now. There may be fewer connections than links. For example, right now
	// all sibling links and the internal link use a shared un-bound connection.
	GetConnections() map[netip.AddrPort]UnderlayConnection

	// GetLinks returns the set of configured distinct links in the provider.
	//
	// Incremental refactoring: this exists so most of the receiving code can stay in-here for now.
	// There may be fewer links than ifIDs. For example, all interfaces owned by one given sibling
	// router are connected via the same link because the remote address is the same.
	GetLinks() map[netip.AddrPort]Link

	// GetLink returns a link that matches the given source address. If the address is not that of
	// a known link, then the internal link is returned.
	//
	// Increamental refactoring: This has to exist until incmoing packets are "demuxed" (i.e.
	// matched with a link), on ingest by the underlay. That would imply moving a part of the
	// runReceiver routine to the underlay. We will do that in the next step.
	GetLink(netip.AddrPort) Link
}

// UnderlayConnection defines the minimum interface that the router expects from an underlay
// connection.
//
// Incremental refactoring: this will eventually be reduced to nothing at all because the sender
// receiver tasks will be part of the underlay.
type UnderlayConnection interface {
	Conn() BatchConn
	Queue() <-chan *Packet
	Name() string
	IfID() uint16
}
