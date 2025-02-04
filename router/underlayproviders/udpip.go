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

package underlayproviders

import (
	"maps"
	"net/netip"

	"github.com/scionproto/scion/router"
)

// provider implements UnderlayProvider by making and returning Udp/Ip links.
//
// This is currently the only implementation. The goal of splitting out this code from the router
// is to enable other implementations. However, as a first step, we continue assuming that the
// batchConn is given to us and is a UDP socket and that, in the case of externalLink, it is bound.
type provider struct {
	allLinks       map[netip.AddrPort]router.Link
	allConnections map[netip.AddrPort]*udpConnection
}

func init() {
	// Register ourselves as an underlay provider. The registration consists of a constructor, not
	// a provider object, because multiple router instances each must have their own underlay
	// provider. The provider is not re-entrant.
	router.AddUnderlay(newProvider)
}

// New instantiates a new instance of the provider for exclusive use by the caller.
func newProvider() router.UnderlayProvider {
	return &provider{
		allLinks:       make(map[netip.AddrPort]router.Link),
		allConnections: make(map[netip.AddrPort]*udpConnection),
	}
}

func (u *provider) Connections() map[netip.AddrPort]router.UnderlayConn {
	// A map of interfaces and a map of concrete implementations aren't compatible.
	// For the same reason, we cannot have the map of concrete implementations as our return type;
	// it does not satisfy the Connections() interface (so much for the "don't return
	// interfaces" rule)... Brilliant, Go.
	// Since we do not want to store our own things as interfaces, we have to translate.
	// Good thing it doesn't happen often.
	m := make(map[netip.AddrPort]router.UnderlayConn)
	for a, c := range u.allConnections {
		m[a] = c // Yeah that's exactly as stupid as it looks.
	}
	return m
}

func (u *provider) Links() map[netip.AddrPort]router.Link {
	return maps.Clone(u.allLinks)
}

func (u *provider) Link(addr netip.AddrPort) router.Link {
	// There is one link for every address. The internal Link catches all.
	l, found := u.allLinks[addr]
	if found {
		return l
	}
	return u.allLinks[netip.AddrPort{}]
}

// udpConnection is simply the combination of a BatchConn and sending queue (plus metadata for
// logs and such). This allows UDP connections to be shared between links. Bundling link and
// connection together is possible and simpler for the code here, but leaks more refactoring changes
// in the main router code. Specifically, either:
//   - sibling links would each need an independent socket to the sibling router, which
//     the router cannot provide at the moment.
//   - the internal links and sibling links would be the same, which means the router needs to
//     special case the sibling links: which we want to remove from the main code.
type udpConnection struct {
	conn  router.BatchConn
	queue chan *router.Packet
	ifID  uint16 // for metrics. All sibling links plus the internal link will be zero, though.
	name  string // for logs. It's more informative than ifID.
}

// TODO(multi_underlay): The following implements UnderlayConn so some of the code
// that needs to interact with it can stay in the main router code. This will be removed in the
// next step

func (u *udpConnection) Conn() router.BatchConn {
	return u.conn
}

func (u *udpConnection) Queue() <-chan *router.Packet {
	return u.queue
}

func (u *udpConnection) Name() string {
	return u.name
}

func (u *udpConnection) IfID() uint16 {
	return u.ifID
}

// todo(jiceatscion): use inheritance between implementations?

type externalLink struct {
	queue      chan<- *router.Packet
	bfdSession router.BFDSession
	ifID       uint16
	remote     netip.AddrPort // We keep this only for Remote()
}

// NewExternalLink returns an external link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready-made and require it to be bound. So, we
// don't keep the remote address, but in the future, we will be making the connections, and
// the conn argument will be gone.
func (u *provider) NewExternalLink(
	conn router.BatchConn,
	qSize int,
	bfd router.BFDSession,
	remote netip.AddrPort,
	ifID uint16,
) router.Link {

	queue := make(chan *router.Packet, qSize)
	c := &udpConnection{
		conn:  conn,
		queue: queue,
		ifID:  ifID,
		name:  remote.String(),
	}
	u.allConnections[remote] = c
	l := &externalLink{
		queue:      queue,
		bfdSession: bfd,
		ifID:       ifID,
	}
	u.allLinks[remote] = l
	return l
}

func (l *externalLink) Scope() router.LinkScope {
	return router.External
}

func (l *externalLink) BFDSession() router.BFDSession {
	return l.bfdSession
}

func (l *externalLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *externalLink) IfID() uint16 {
	return l.ifID
}

func (l *externalLink) Remote() netip.AddrPort {
	return l.remote
}

func (l *externalLink) Send(p *router.Packet) bool {
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

func (l *externalLink) SendBlocking(p *router.Packet) {
	l.queue <- p
}

type siblingLink struct {
	queue      chan<- *router.Packet
	bfdSession router.BFDSession
	remote     netip.AddrPort
}

// newSiblingLink returns a sibling link over the UdpIpUnderlay.
//
// TODO(multi_underlay): this can only be an improvement over internalLink if we have a bound
// batchConn with the sibling router. However, currently the caller doesn't have one to give us;
// the main code has so far been reusing the internal connection. So, that's what we do for now.
// As a result, we keep the remote address; as we need to supply it for every packet being sent
// (something we will get rid of eventually).
// In the future we will be making one connection per remote address and we might even be able
// to erase the separation between link and connection for this implementation. Side effect
// of moving the address:link map here: the router does not know if there is an existing link. As
// a result it has to give us a BFDSession in all cases and we might throw it away (there
// are no permanent resources attached to it). This will be fixed by moving some BFD related code
// in-here.
func (u *provider) NewSiblingLink(
	qSize int, bfd router.BFDSession, remote netip.AddrPort) router.Link {

	// There is exactly one sibling link per sibling router address.
	l, exists := u.allLinks[remote]
	if exists {
		return l.(*siblingLink)
	}

	// All sibling links re-use the internal connection. This used to be a late binding (packets to
	// siblings would get routed through the internal interface at run-time). But now this binding
	// happens right now and it can't work if this is called before newInternalLink.
	c, exists := u.allConnections[netip.AddrPort{}]
	if !exists {
		// TODO(multi_underlay):That doesn't actually happen.
		// It is only required until we stop sharing the internal connection.
		panic("newSiblingLink called before newInternalLink")
	}

	s := &siblingLink{
		queue:      c.queue,
		bfdSession: bfd,
		remote:     remote,
	}
	u.allLinks[remote] = s
	return s
}

func (l *siblingLink) Scope() router.LinkScope {
	return router.Sibling
}

func (l *siblingLink) BFDSession() router.BFDSession {
	return l.bfdSession
}

func (l *siblingLink) IsUp() bool {
	return l.bfdSession == nil || l.bfdSession.IsUp()
}

func (l *siblingLink) IfID() uint16 {
	return 0
}

func (l *siblingLink) Remote() netip.AddrPort {
	return l.remote
}

func (l *siblingLink) Send(p *router.Packet) bool {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromAddrPort(p.DstAddr, l.remote)
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

func (l *siblingLink) SendBlocking(p *router.Packet) {
	// We use an unbound connection but we offer a connection-oriented service. So, we need to
	// supply the packet's destination address.
	router.UpdateNetAddrFromAddrPort(p.DstAddr, l.remote)
	l.queue <- p
}

type internalLink struct {
	queue chan *router.Packet
}

// newSiblingLink returns a sibling link over the UdpIpUnderlay.
//
// TODO(multi_underlay): we get the connection ready made. In the future we will be making it
// and the conn argument will be gone.
func (u *provider) NewInternalLink(conn router.BatchConn, qSize int) router.Link {
	queue := make(chan *router.Packet, qSize)
	c := &udpConnection{
		conn:  conn,
		queue: queue,
		name:  "internal",
		ifID:  0,
	}
	u.allConnections[netip.AddrPort{}] = c
	l := &internalLink{
		queue: queue,
	}
	u.allLinks[netip.AddrPort{}] = l
	return l
}

func (l *internalLink) Scope() router.LinkScope {
	return router.Internal
}

func (l *internalLink) IsUp() bool {
	return true
}

func (l *internalLink) BFDSession() router.BFDSession {
	return nil
}

func (l *internalLink) IfID() uint16 {
	return 0
}

func (l *internalLink) Remote() netip.AddrPort {
	return netip.AddrPort{}
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) Send(p *router.Packet) bool {
	select {
	case l.queue <- p:
	default:
		return false
	}
	return true
}

// The packet's destination is already in the packet's meta-data.
func (l *internalLink) SendBlocking(p *router.Packet) {
	l.queue <- p
}
