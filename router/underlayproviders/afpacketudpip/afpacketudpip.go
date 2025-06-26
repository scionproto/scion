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

package afpacketudpip

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/private/underlay/ebpf"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

var (
	errResolveOnNonInternalLink = errors.New("unsupported address resolution on link not internal")
	errInvalidServiceAddress    = errors.New("invalid service address")
	errShortPacket              = errors.New("packet is too short")
	errDuplicateRemote          = errors.New("duplicate remote address")
)

// udpConnFilters holds the port filter handles.
// There are scalability concerns regarding the kFilter (attached directly to an interface):  only
// a limited number of filters can be attached to an interface and it is inefficient to have many.
// Deduplication is accomplished for free as a result of deduplicating udpConnections: we create
// only one per interface and add ports to the single filter as we add links sharing it.
type udpConnFilters struct {
	kFilter *ebpf.KFilterHandle
	sFilter *ebpf.SFilterHandle
}

func (uf udpConnFilters) AddDst(dst *netip.AddrPort) {
	uf.kFilter.AddAddrPort(*dst)
	uf.sFilter.AddPort(dst.Port())
}

func (uf udpConnFilters) Close() {
	uf.kFilter.Close()
	uf.sFilter.Close()
}

// An interface to enable unit testing of this specific underlay implementation.
// (Well... that would still be hard - To be improved).
type ConnOpener interface {
	// Creates a connection as specified.
	Open(index int) (*afpacket.TPacket, udpConnFilters, error)
}

// The default ConnOpener for this underlay: opens a afpacket socket.
type udpOpener struct{}

func (uo udpOpener) Open(index int) (*afpacket.TPacket, udpConnFilters, error) {
	intf, err := net.InterfaceByIndex(index)
	if err != nil {
		return nil, udpConnFilters{}, serrors.Wrap("finding interface", err)
	}

	// We have to make the TPacket non-blocking because it needs to be drained of packets after
	// adding the filter. We use a longish timeout since the rest of the time we don't actually want
	// to wake up.  Caution: an afpacket socket normally receives its own outgoing traffic.
	// mpkSender configures the socket to avoid that but if you ever remove mpkSender, you
	// need to do something about it. The bpf does *not* do it either and should not. It is
	// inefficient.
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(intf.Name),
		afpacket.OptPollTimeout(200*time.Millisecond),
		// afpacket.OptFrameSize(intf.MTU), // Constrained. default is probably best
	)
	if err != nil {
		return nil, udpConnFilters{}, serrors.Wrap("creating TPacket", err)
	}

	kFilter, err := ebpf.BpfKFilter(index)
	if err != nil {
		return nil, udpConnFilters{}, serrors.Wrap(fmt.Sprintf(
			"adding port filter to interface %s", intf.Name,
		), err)
	}
	sFilter, err := ebpf.BpfSFilter(handle)
	if err != nil {
		return nil, udpConnFilters{}, serrors.Wrap(fmt.Sprintf(
			"adding port filter to rawSocket %s", intf.Name), err)
	}

	// Drain
	for {
		_, _, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
	}
	log.Debug("Added port filter to interface", "name", intf.Name)
	return handle, udpConnFilters{kFilter, sFilter}, nil
}

// provider implements UnderlayProvider by making and returning Udp/Ip links on top of
// packet sockets.
type provider struct {
	mu                sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize         int
	allLinks          map[netip.AddrPort]udpLink
	allConnections    map[int]*udpConnection // One per network interface and port combination.
	connOpener        ConnOpener             // uo{}, except for unit tests
	svc               *router.Services[netip.AddrPort]
	receiveBufferSize int
	sendBufferSize    int
	dispatchStart     uint16
	dispatchEnd       uint16
	dispatchRedirect  uint16
}

type udpLink interface {
	router.Link
	start(ctx context.Context, procQs []chan *router.Packet, pool router.PacketPool)
	stop()
	receive(srcAddr *netip.AddrPort, dstIP netip.Addr, p *router.Packet)
	handleNeighbor(isReq bool, targetIP, senderIP, rcptIP netip.Addr, remoteHw [6]byte)
}

func init() {
	// Register ourselves as an underlay provider. The registration consists of a factory, not
	// a provider object, because multiple router instances each must have their own underlay
	// provider. The provider is not re-entrant.

	// We add ourselves as an implementation of the "udpip" underlay. The two udpip underlays
	// are interchangeable. Only this one should perform better but exists only for Linux.
	// The priorities cause the router to chose this one over the other when both are available.
	router.AddUnderlay("udpip", providerFactory{})
}

// Implement router.ProviderFactory
type providerFactory struct{}

// New instantiates a new instance of the provider for exclusive use by the caller.
// TODO(multi_underlay): batchSize should be an underlay-specific config.
func (providerFactory) New(
	batchSize int,
	receiveBufferSize int,
	sendBufferSize int,
) router.UnderlayProvider {
	return &provider{
		batchSize:         batchSize,
		allLinks:          make(map[netip.AddrPort]udpLink),
		allConnections:    make(map[int]*udpConnection),
		connOpener:        udpOpener{},
		svc:               router.NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
	}
}

func (providerFactory) Priority() int {
	return 2 // Until we know this works, make ourselves scarce
}

// SetConnOpener installs the given opener. opener must be an implementation of ConnOpener or
// panic will ensue. Only for use in unit tests.
func (u *provider) SetConnOpener(opener any) {
	u.connOpener = opener.(ConnOpener)
}

func (u *provider) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

func (u *provider) Headroom() int {

	// We advise of enough headroom for ethernet + max(ip) + udp headers on outgoing packets (we do
	// not need to add extensions and do not use options). On receipt, we cannot predict if the IP
	// header is v4 or v6 or has options or extensions. We align the packet with the assumtion that
	// it is v4 with no options. As a result, the payload never starts earlier than planned. This is
	// needed to ensure that the headroom we leave is never less than the worst case requirement
	// across all underlays.

	return 14 + 40 + 8 // ethernet + basic ipv6 + udp
}

func (u *provider) SetDispatchPorts(start, end, redirect uint16) {
	log.Debug("SetDispactherPorts", "start", start, "end", end, "redirect", redirect)
	u.dispatchStart = start
	u.dispatchEnd = end
	u.dispatchRedirect = redirect
}

// AddSvc adds the address for the given service.
func (u *provider) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	// We pre-resolve the addresses, which is trivial for this underlay.
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.AddSvc(svc, addr)
	return nil
}

// DelSvc deletes the address for the given service.
func (u *provider) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.DelSvc(svc, addr)
	return nil
}

// The queues to be used by the receiver task are supplied at this point because they must be
// sized according to the number of connections that will be started.
func (u *provider) Start(
	ctx context.Context, pool router.PacketPool, procQs []chan *router.Packet,
) {
	u.mu.Lock()
	if len(procQs) == 0 {
		// Pointless to run without any processor of incoming traffic
		return
	}
	connSnapshot := slices.Collect(maps.Values(u.allConnections))
	linkSnapshot := slices.Collect(maps.Values(u.allLinks))
	u.mu.Unlock()

	// Links MUST be started before connections. Given that this is an internal mater, we don't pay
	// the price of checking at use time.
	for _, l := range linkSnapshot {
		l.start(ctx, procQs, pool)
	}
	for _, c := range connSnapshot {
		c.start(u.batchSize, pool)
	}
}

func (u *provider) Stop() {
	u.mu.Lock()
	connSnapshot := slices.Collect(maps.Values(u.allConnections))
	linkSnapshot := slices.Collect(maps.Values(u.allLinks))
	u.mu.Unlock()

	for _, c := range connSnapshot {
		c.stop()
	}
	for _, l := range linkSnapshot {
		l.stop()
	}
}

// addMcastGrp adds the given (TPacket, interface) pair to the given multicast group.
func addMcastGrp(tp *afpacket.TPacket, ifIndex int, mcastAddr net.HardwareAddr) {
	// Unceremonious but necessary until we submit a change (which would have to be more general
	// than this) to the afpacket project and get it merged.
	fdv := reflect.ValueOf(tp).Elem().FieldByName("fd")
	tpfd := int(fdv.Int())

	mreq := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_MULTICAST,
		Alen:    6,
	}
	copy(mreq.Address[0:6], mcastAddr[:])

	opt := unix.PACKET_ADD_MEMBERSHIP

	if err := unix.SetsockoptPacketMreq(tpfd, unix.SOL_PACKET, opt, &mreq); err != nil {
		panic(err)
	}
}

// getUdpConnection returns the appropriate udpConnection; creating it if it doesn't exist yet.
func (u *provider) getUdpConnection(
	qSize int, local *netip.AddrPort,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {

	localAddr := local.Addr()
	localAddrStr := localAddr.String()

	// TODO(jiceatscion): We don't really need to go through every interface every time.
	interfaces, _ := net.Interfaces()
	for _, intf := range interfaces {
		if addrs, err := intf.Addrs(); err == nil {
			for _, addr := range addrs {
				// net.Addr is very generic. We have to take a guess (educated by reading the code)
				// at what the underlying type is to make our comparison.
				ipNet, ok := addr.(*net.IPNet)
				if ok {
					// We match loopback addresses to the lo interface in support of how
					// we configure test topologies when running with the supervisor: loopack
					// addresses are not explicitly assigned. There is exactly one udpConnection
					// per socket, one socket per interface.
					if ipNet.IP.String() == localAddrStr ||
						(localAddr.IsLoopback() && intf.Name == "lo") {

						c := u.allConnections[intf.Index]
						if c == nil {
							log.Debug("New UDP connection created", "addr", localAddrStr,
								"interface", intf.Name)
							c, err = newUdpConnection(intf, qSize, u.connOpener, metrics)
							if err != nil {
								return nil, err
							}
							u.allConnections[intf.Index] = c
						}
						c.connFilters.AddDst(local)
						if localAddr.Is6() {
							addrBytes := localAddr.As16()
							mcastGrp := net.HardwareAddr{
								0x33, 0x33, ndpMcastPrefix[12],
								addrBytes[13], addrBytes[14], addrBytes[15],
							}
							addMcastGrp(c.afp, intf.Index, mcastGrp)
						}
						return c, nil
					}
				}
			}
		}
	}

	return nil, errors.New("No interface with the requested address")
}

// NewExternalLink returns an external link over the UDP/IP underlay. It is implemented with a
// ptpLink and has a specific ifID.
func (u *provider) NewExternalLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	ifID uint16,
	metrics *router.InterfaceMetrics,
) (router.Link, error) {
	localAddr, err := conn.ResolveAddrPortOrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	remoteAddr, err := conn.ResolveAddrPort(remote)
	if err != nil {
		return nil, serrors.Wrap("resolving remote address", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// Duplicate external links are not supported. That they happen at all would denote a serious
	// configuration error.
	if l := u.allLinks[remoteAddr]; l != nil {
		return nil, serrors.Join(errDuplicateRemote, nil, "addr", remote)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkExternal(&localAddr, &remoteAddr, c, bfd, ifID, metrics)
	u.allLinks[remoteAddr] = l
	return l, nil
}

// NewSiblingLink returns an external link over the UDP/IP underlay. It is implemented with a
// ptpLink and has the unspecified ifID: 0.
//
// We de-duplicate sibling links. The router gives us a BFDSession in all cases and we might throw
// it away (there are no persistent resources attached to it). This could be fixed by moving some
// BFD related code in-here.
func (u *provider) NewSiblingLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	metrics *router.InterfaceMetrics,
) (router.Link, error) {
	localAddr, err := conn.ResolveAddrPortOrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	remoteAddr, err := conn.ResolveAddrPort(remote)
	if err != nil {
		return nil, serrors.Wrap("resolving remote address", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// We silently deduplicate sibling links, so the router doesn't need to be aware or keep track
	// of link sharing.
	if l := u.allLinks[remoteAddr]; l != nil {
		return l, nil
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkSibling(&localAddr, &remoteAddr, c, bfd, metrics)
	u.allLinks[remoteAddr] = l
	return l, nil
}

// NewInternalLink returns a internal link over the UdpIpUnderlay. The link implementation has
// no fixed peer. It finds the destination address in the packet structure. Unlike ptpLink, it
// can resolve a SCION peer address to a local underlay address; via the dispatcher if needed.
func (u *provider) NewInternalLink(
	local string, qSize int, metrics *router.InterfaceMetrics,
) (router.Link, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	localAddr, err := conn.ResolveAddrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, metrics)
	if err != nil {
		return nil, err
	}

	il := newInternalLink(
		&localAddr, c, u.svc, u.dispatchStart, u.dispatchEnd, u.dispatchRedirect, metrics)
	u.allLinks[netip.AddrPort{}] = il
	return il, nil
}

// Technically, this is a layering violation. We're peeking into the SCION packet for the
// flowID...oh well.
func computeProcID(data []byte, numProcRoutines int, hashSeed uint32) (uint32, error) {
	if len(data) < slayers.CmnHdrLen {
		return 0, errShortPacket
	}
	dstHostAddrLen := slayers.AddrType(data[9] >> 4 & 0xf).Length()
	srcHostAddrLen := slayers.AddrType(data[9] & 0xf).Length()
	addrHdrLen := 2*addr.IABytes + srcHostAddrLen + dstHostAddrLen
	if len(data) < slayers.CmnHdrLen+addrHdrLen {
		return 0, errShortPacket
	}

	s := hashSeed

	// inject the flowID
	s = hashFNV1a(s, data[1]&0xF) // The left 4 bits aren't part of the flowID.
	for _, c := range data[2:4] {
		s = hashFNV1a(s, c)
	}

	// Inject the src/dst addresses
	for _, c := range data[slayers.CmnHdrLen : slayers.CmnHdrLen+addrHdrLen] {
		s = hashFNV1a(s, c)
	}

	return s % uint32(numProcRoutines), nil
}
