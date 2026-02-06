// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package afxdpudpip

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/underlay/afxdp"
	"github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/bfd"
)

const (
	ethLen      = 14
	ipv4Len     = 20
	ipv6Len     = 40
	ipv6AddrLen = 16

	udpLen  = 8
	portLen = 2

	// AF_XDP specific defaults
	defaultNumFrames = 4096
	defaultFrameSize = 2048
	defaultBatchSize = 64
)

var (
	errResolveOnNonInternalLink = errors.New(
		"unsupported address resolution on link not internal",
	)
	errInvalidServiceAddress = errors.New("invalid service address")
	errShortPacket           = errors.New("packet is too short")
	errDuplicateRemote       = errors.New("duplicate remote address")
)

// connectionKey uniquely identifies an AF_XDP connection by interface index and queue ID.
type connectionKey struct {
	ifIndex int
	queueID uint32
}

// ConnOpener is an interface to enable unit testing of
// this specific underlay implementation.
type ConnOpener interface {
	// Open creates an AF_XDP socket on the given interface and queue.
	Open(
		ifIndex int, queueID uint32,
		xdpInterface *afxdp.Interface,
	) (*afxdp.Socket, error)
}

// udpOpener is the default ConnOpener: opens an AF_XDP socket.
type udpOpener struct {
	preferZerocopy  bool
	preferHugepages bool
}

func (uo udpOpener) Open(
	ifIndex int, queueID uint32, xdpInterface *afxdp.Interface,
) (*afxdp.Socket, error) {
	conf := afxdp.SocketConfig{
		QueueID:   queueID,
		NumFrames: defaultNumFrames,
		FrameSize: defaultFrameSize,
		RxSize:    2048,
		TxSize:    2048,
		CqSize:    2048,
		BatchSize: defaultBatchSize,
	}

	socket, err := afxdp.Open(conf, xdpInterface, uo.preferHugepages, uo.preferZerocopy)
	if err != nil {
		return nil, serrors.Wrap("opening AF_XDP socket", err)
	}

	log.Debug("Opened AF_XDP socket",
		"queue", queueID,
		"zerocopy", socket.IsZerocopy(),
		"hugepages", socket.IsHugepages())
	return socket, nil
}

// underlay implements router.Underlay in AF_XDP sockets for high-performance packet I/O.
// ARP/NDP is handled by the kernel via XDP_PASS in the sockfilter eBPF program.
type underlay struct {
	mu        sync.Mutex // Prevents race between adding connections and Start/Stop.
	batchSize int
	allLinks  map[netip.AddrPort]udpLink

	// allConnections maps one per (interface, queue) pair.
	allConnections map[connectionKey]*udpConnection
	// connOpener is udpOpener{}, except for unit tests
	connOpener        ConnOpener
	svc               *router.Services[netip.AddrPort]
	receiveBufferSize int
	sendBufferSize    int
	dispatchStart     uint16
	dispatchEnd       uint16
	dispatchRedirect  uint16
	preferZerocopy    bool
	preferHugepages   bool
}

type udpLink interface {
	router.Link
	start(ctx context.Context, procQs []chan *router.Packet, pool router.PacketPool)
	stop()
	receive(p *router.Packet)
}

func init() {
	// Register ourselves as an underlay provider. This implementation uses AF_XDP
	// for high-performance zero-copy packet I/O on Linux with compatible NICs.
	// ARP/NDP is delegated to the kernel (XDP_PASS in sockfilter.c).
	router.AddUnderlayProvider("udpip:afxdp", underlayProvider{})
}

// underlayProvider implements router.ProviderFactory.
type underlayProvider struct{}

// New instantiates a new instance of the provider for exclusive use by the caller.
func (underlayProvider) New(
	batchSize int,
	receiveBufferSize int,
	sendBufferSize int,
) router.Underlay {
	return &underlay{
		batchSize:         batchSize,
		allLinks:          make(map[netip.AddrPort]udpLink),
		allConnections:    make(map[connectionKey]*udpConnection),
		connOpener:        udpOpener{preferZerocopy: true, preferHugepages: true},
		svc:               router.NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
		preferZerocopy:    true,
		preferHugepages:   true,
	}
}

// SetConnOpener installs the given opener. opener must be an implementation of
// ConnOpener or panic will ensue. Only for use in unit tests.
func (u *underlay) SetConnOpener(opener any) {
	u.connOpener = opener.(ConnOpener)
}

func (u *underlay) NumConnections() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.allLinks)
}

func (u *underlay) Headroom() int {
	// Enough headroom for ethernet + max(ip) + udp headers on outgoing packets.
	// We add src address + port for internal links (packet.HeadBytes storage).
	return ethLen + ipv6Len + udpLen + ipv6AddrLen + portLen
}

func (u *underlay) SetDispatchPorts(start, end, redirect uint16) {
	log.Debug("SetDispatcherPorts", "start", start, "end", end, "redirect", redirect)
	u.dispatchStart = start
	u.dispatchEnd = end
	u.dispatchRedirect = redirect
}

// AddSvc adds the address for the given service.
func (u *underlay) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.AddSvc(svc, addr)
	return nil
}

// DelSvc deletes the address for the given service.
func (u *underlay) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	addr := netip.AddrPortFrom(host.IP(), port)
	if !addr.IsValid() {
		return errInvalidServiceAddress
	}
	u.svc.DelSvc(svc, addr)
	return nil
}

// Start activates all connections and links.
func (u *underlay) Start(
	ctx context.Context, pool router.PacketPool, procQs []chan *router.Packet,
) {
	u.mu.Lock()
	if len(procQs) == 0 {
		return
	}
	connSnapshot := slices.Collect(maps.Values(u.allConnections))
	linkSnapshot := slices.Collect(maps.Values(u.allLinks))
	u.mu.Unlock()

	// Links MUST be started before connections.
	for _, l := range linkSnapshot {
		l.start(ctx, procQs, pool)
	}
	for _, c := range connSnapshot {
		c.start(u.batchSize, pool)
	}
}

func (u *underlay) Stop() {
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

// computeProcID hashes the SCION flow ID and addresses to determine the processor queue.
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
	s = router.HashFNV1a(s, data[1]&0xF)
	for _, c := range data[2:4] {
		s = router.HashFNV1a(s, c)
	}
	for _, c := range data[slayers.CmnHdrLen : slayers.CmnHdrLen+addrHdrLen] {
		s = router.HashFNV1a(s, c)
	}

	return s % uint32(numProcRoutines), nil
}

// getUdpConnection returns the appropriate udpConnection; creating it if it doesn't
// exist yet. The queueID specifies which NIC queue to bind the AF_XDP socket to.
func (u *underlay) getUdpConnection(
	qSize int, local *netip.AddrPort, queueID uint32,
	metrics *router.InterfaceMetrics,
) (*udpConnection, error) {
	localAddr := local.Addr()
	localAddrStr := localAddr.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range interfaces {
		if addrs, err := intf.Addrs(); err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok {
					if ipNet.IP.String() == localAddrStr ||
						(localAddr.IsLoopback() && intf.Name == "lo") {

						key := connectionKey{ifIndex: intf.Index, queueID: queueID}
						c := u.allConnections[key]
						if c == nil {
							log.Debug("New AF_XDP connection created",
								"addr", localAddrStr,
								"interface", intf.Name,
								"queue", queueID)
							c, err = newUdpConnection(
								intf, queueID, qSize, u.connOpener, metrics,
							)
							if err != nil {
								return nil, err
							}
							u.allConnections[key] = c
						}
						// Add the destination address/port to the XDP filter.
						if err := c.xdpInterface.AddAddrPort(*local); err != nil {
							return nil, serrors.Wrap("adding address to XDP filter", err)
						}
						return c, nil
					}
				}
			}
		}
	}

	return nil, errors.New("no interface with the requested address")
}

// NewExternalLink returns an external link over the UDP/IP underlay.
// The options string can contain "queue=N" to specify the NIC queue for AF_XDP.
func (u *underlay) NewExternalLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	options string,
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
	queueID, err := parseOptions(options)
	if err != nil {
		return nil, serrors.Wrap("parsing options", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if l := u.allLinks[remoteAddr]; l != nil {
		return nil, serrors.Join(errDuplicateRemote, nil, "addr", remote)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, queueID, metrics)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkExternal(&localAddr, &remoteAddr, c, bfd, ifID, metrics)
	u.allLinks[remoteAddr] = l
	return l, nil
}

// NewSiblingLink returns a sibling link over the UDP/IP underlay.
// The options string can contain "queue=N" to specify the NIC queue for AF_XDP.
func (u *underlay) NewSiblingLink(
	qSize int,
	bfd *bfd.Session,
	local string,
	remote string,
	options string,
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
	queueID, err := parseOptions(options)
	if err != nil {
		return nil, serrors.Wrap("parsing options", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if l := u.allLinks[remoteAddr]; l != nil {
		return l, nil
	}
	c, err := u.getUdpConnection(qSize, &localAddr, queueID, metrics)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkSibling(&localAddr, &remoteAddr, c, bfd, metrics)
	u.allLinks[remoteAddr] = l
	return l, nil
}

// NewInternalLink returns an internal link over the UDP/IP underlay.
// Internal links use queue 0 by default as they typically use loopback.
func (u *underlay) NewInternalLink(
	local string, qSize int, metrics *router.InterfaceMetrics,
) (router.Link, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	localAddr, err := conn.ResolveAddrPort(local)
	if err != nil {
		return nil, serrors.Wrap("resolving local address", err)
	}
	c, err := u.getUdpConnection(qSize, &localAddr, 0, metrics)
	if err != nil {
		return nil, err
	}

	il := newInternalLink(
		&localAddr, c, u.svc, u.dispatchStart, u.dispatchEnd, u.dispatchRedirect, metrics,
	)
	u.allLinks[netip.AddrPort{}] = il
	return il, nil
}
