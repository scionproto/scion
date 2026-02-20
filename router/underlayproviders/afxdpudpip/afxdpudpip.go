// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
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

	// AF_XDP specific default for connection receive batch size.
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
	numFrames       uint32
	frameSize       uint32
	rxSize          uint32
	txSize          uint32
	cqSize          uint32
	batchSize       uint32
}

func (uo udpOpener) Open(
	ifIndex int, queueID uint32, xdpInterface *afxdp.Interface,
) (*afxdp.Socket, error) {
	conf := afxdp.SocketConfig{
		QueueID:   queueID,
		NumFrames: uo.numFrames,
		FrameSize: uo.frameSize,
		RxSize:    uo.rxSize,
		TxSize:    uo.txSize,
		CqSize:    uo.cqSize,
		BatchSize: uo.batchSize,
	}

	socket, err := afxdp.Open(conf, xdpInterface, uo.preferHugepages, uo.preferZerocopy)
	if err != nil {
		return nil, serrors.Wrap("opening AF_XDP socket", err)
	}

	if uo.preferZerocopy && !socket.IsZerocopy() {
		log.Info("AF_XDP zerocopy not supported, falling back to copy mode",
			"queue", queueID)
	}
	if uo.preferHugepages && !socket.IsHugepages() {
		log.Info("AF_XDP hugepages not available, falling back to normal pages",
			"queue", queueID)
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
	// allInterfaces maps one XDP interface per NIC (keyed by ifIndex).
	// Multiple connections on the same NIC share one XDP interface.
	allInterfaces map[int]*afxdp.Interface
	// connOpener is udpOpener{}, except for unit tests
	connOpener        ConnOpener
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
		allInterfaces:     make(map[int]*afxdp.Interface),
		connOpener:        udpOpener{preferZerocopy: true, preferHugepages: true},
		svc:               router.NewServices[netip.AddrPort](),
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
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
	return len(u.allConnections)
}

func (u *underlay) Headroom() int {
	// Enough headroom for ethernet + max(ip) + udp headers on outgoing packets.
	// We add src address + port for internal links (packet.HeadBytes storage).
	return ethLen + ipv6Len + udpLen + ipv6AddrLen + portLen
}

// applyPreferences updates the connOpener with preferences from the given options.
// Only affects udpOpener; test openers are left untouched. Caller must hold u.mu.
func (u *underlay) applyPreferences(opts Options) {
	opener, ok := u.connOpener.(udpOpener)
	if !ok {
		return
	}
	changed := false
	if opts.PreferZerocopy != nil {
		opener.preferZerocopy = *opts.PreferZerocopy
		changed = true
	}
	if opts.PreferHugepages != nil {
		opener.preferHugepages = *opts.PreferHugepages
		changed = true
	}
	if opts.NumFrames != nil {
		opener.numFrames = *opts.NumFrames
		changed = true
	}
	if opts.FrameSize != nil {
		opener.frameSize = *opts.FrameSize
		changed = true
	}
	if opts.RxSize != nil {
		opener.rxSize = *opts.RxSize
		changed = true
	}
	if opts.TxSize != nil {
		opener.txSize = *opts.TxSize
		changed = true
	}
	if opts.CqSize != nil {
		opener.cqSize = *opts.CqSize
		changed = true
	}
	if opts.BatchSize != nil {
		opener.batchSize = *opts.BatchSize
		changed = true
	}
	if changed {
		u.connOpener = opener
	}
}

func (u *underlay) SetDispatchPorts(start, end, redirect uint16) {
	log.Debug("SetDispatchPorts", "start", start, "end", end, "redirect", redirect)
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
		u.mu.Unlock()
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
	ifaceSnapshot := slices.Collect(maps.Values(u.allInterfaces))
	u.mu.Unlock()

	for _, c := range connSnapshot {
		c.stop()
	}
	for _, l := range linkSnapshot {
		l.stop()
	}
	// Close shared XDP interfaces after all sockets are closed.
	for _, xi := range ifaceSnapshot {
		xi.Close()
	}
}

// receivePacket updates input metrics, hashes the packet to a processor queue,
// and enqueues it.
func receivePacket(
	p *router.Packet,
	link router.Link,
	metrics *router.InterfaceMetrics,
	procQs []chan *router.Packet,
	seed uint32,
	pool router.PacketPool,
) {
	sc := router.ClassOfSize(len(p.RawPacket))
	metrics[sc].InputPacketsTotal.Inc()
	metrics[sc].InputBytesTotal.Add(float64(len(p.RawPacket)))
	procID, err := computeProcID(p.RawPacket, len(procQs), seed)
	if err != nil {
		log.Debug("Error while computing procID", "err", err)
		pool.Put(p)
		metrics[sc].DroppedPacketsInvalid.Inc()
		return
	}

	p.Link = link

	select {
	case procQs[procID] <- p:
	default:
		pool.Put(p)
		metrics[sc].DroppedPacketsBusyProcessor.Inc()
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

// computeConnIdx hashes the SCION flow ID and addresses to select a connection
// for TX. This ensures packets from the same flow always use the same queue,
// preventing reordering.
func computeConnIdx(data []byte, numConns int, seed uint32) int {
	if numConns <= 1 {
		return 0
	}
	idx, err := computeProcID(data, numConns, seed)
	if err != nil {
		return 0
	}
	return int(idx)
}

// detectQueues reads sysfs to discover available RX and TX queues for a network interface.
// Returns sorted lists of queue IDs. Each falls back to [0] independently if detection fails.
func detectQueues(ifName string) (rx, tx []uint32) {
	entries, err := os.ReadDir(fmt.Sprintf("/sys/class/net/%s/queues", ifName))
	if err != nil {
		log.Debug("Cannot read NIC queues from sysfs, using queue 0",
			"interface", ifName, "err", err)
		return []uint32{0}, []uint32{0}
	}

	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "rx-") {
			id, err := strconv.ParseUint(strings.TrimPrefix(name, "rx-"), 10, 32)
			if err != nil {
				continue
			}
			rx = append(rx, uint32(id))
		} else if strings.HasPrefix(name, "tx-") {
			id, err := strconv.ParseUint(strings.TrimPrefix(name, "tx-"), 10, 32)
			if err != nil {
				continue
			}
			tx = append(tx, uint32(id))
		}
	}

	if len(rx) == 0 {
		log.Debug("No RX queues found in sysfs, using queue 0",
			"interface", ifName)
		rx = []uint32{0}
	}
	if len(tx) == 0 {
		log.Debug("No TX queues found in sysfs, using queue 0",
			"interface", ifName)
		tx = []uint32{0}
	}

	slices.Sort(rx)
	slices.Sort(tx)
	log.Debug("Auto-detected NIC queues",
		"interface", ifName, "rx_queues", rx, "tx_queues", tx)
	return rx, tx
}

// getOrCreateInterface returns the shared XDP interface for the given NIC,
// creating and attaching the XDP program if this is the first use.
// Caller must hold u.mu.
func (u *underlay) getOrCreateInterface(intf net.Interface) (*afxdp.Interface, error) {
	xi := u.allInterfaces[intf.Index]
	if xi != nil {
		return xi, nil
	}
	xi, err := afxdp.NewInterface(intf.Name)
	if err != nil {
		return nil, serrors.Wrap("creating XDP interface", err,
			"interface", intf.Name)
	}
	u.allInterfaces[intf.Index] = xi
	return xi, nil
}

// getUdpConnections returns the appropriate udpConnections for the given address
// and queue IDs; creating them if they don't exist. rxQueueIDs and txQueueIDs
// may overlap; shared queue IDs reuse the same connection. If either slice is nil,
// the corresponding queues are auto-detected from sysfs.
func (u *underlay) getUdpConnections(
	qSize int, local *netip.AddrPort,
	rxQueueIDs, txQueueIDs []uint32,
	metrics *router.InterfaceMetrics,
) (rxConns, txConns []*udpConnection, err error) {
	localAddr := local.Addr()
	localAddrStr := localAddr.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, intf := range interfaces {
		if addrs, err := intf.Addrs(); err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok {
					if ipNet.IP.String() == localAddrStr ||
						(localAddr.IsLoopback() && intf.Name == "lo") {

						// Auto-detect queues if not explicitly specified.
						if len(rxQueueIDs) == 0 || len(txQueueIDs) == 0 {
							detectedRx, detectedTx := detectQueues(intf.Name)
							if len(rxQueueIDs) == 0 {
								rxQueueIDs = detectedRx
							}
							if len(txQueueIDs) == 0 {
								txQueueIDs = detectedTx
							}
						}

						// Get or create the shared XDP interface for this NIC.
						xi, err := u.getOrCreateInterface(intf)
						if err != nil {
							return nil, nil, err
						}

						// Add the destination address/port to the XDP filter.
						if err := xi.AddAddrPort(*local); err != nil {
							return nil, nil, serrors.Wrap(
								"adding address to XDP filter", err)
						}

						// Collect all unique queue IDs (union of RX and TX).
						allQueueIDs := make(map[uint32]struct{},
							len(rxQueueIDs)+len(txQueueIDs))
						for _, q := range rxQueueIDs {
							allQueueIDs[q] = struct{}{}
						}
						for _, q := range txQueueIDs {
							allQueueIDs[q] = struct{}{}
						}

						// Create/reuse a connection for each unique queue ID.
						connByQueue := make(map[uint32]*udpConnection, len(allQueueIDs))
						for qID := range allQueueIDs {
							key := connectionKey{
								ifIndex: intf.Index,
								queueID: qID,
							}
							c := u.allConnections[key]
							if c == nil {
								log.Debug("New AF_XDP connection created",
									"addr", localAddrStr,
									"interface", intf.Name,
									"queue", qID)
								c, err = newUdpConnection(
									intf, qID, qSize,
									u.connOpener, xi, metrics,
								)
								if err != nil {
									return nil, nil, err
								}
								u.allConnections[key] = c
							}
							connByQueue[qID] = c
						}

						// Build rxConns and txConns preserving the
						// order of the requested queue IDs.
						rxConns = make([]*udpConnection, len(rxQueueIDs))
						for i, qID := range rxQueueIDs {
							rxConns[i] = connByQueue[qID]
						}
						txConns = make([]*udpConnection, len(txQueueIDs))
						for i, qID := range txQueueIDs {
							txConns[i] = connByQueue[qID]
						}
						return rxConns, txConns, nil
					}
				}
			}
		}
	}

	return nil, nil, errors.New("no interface with the requested address")
}

// NewExternalLink returns an external link over the UDP/IP underlay.
// The options string is a JSON object that may contain "rx_queues", "tx_queues",
// "prefer_zerocopy", "prefer_hugepages", "num_frames", "frame_size", "rx_size",
// "tx_size", "cq_size", and "batch_size" fields. If no queues are specified,
// all available queues are auto-detected from sysfs.
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
	opts, err := parseOptions(options)
	if err != nil {
		return nil, serrors.Wrap("parsing options", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.applyPreferences(opts)

	if l := u.allLinks[remoteAddr]; l != nil {
		return nil, serrors.Join(errDuplicateRemote, nil, "addr", remote)
	}
	rxConns, txConns, err := u.getUdpConnections(
		qSize, &localAddr, opts.RxQueues, opts.TxQueues, metrics,
	)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkExternal(&localAddr, &remoteAddr, rxConns, txConns, bfd, ifID, metrics)
	u.allLinks[remoteAddr] = l
	return l, nil
}

// NewSiblingLink returns a sibling link over the UDP/IP underlay.
// The options string is a JSON object that may contain "rx_queues", "tx_queues",
// "prefer_zerocopy", "prefer_hugepages", "num_frames", "frame_size", "rx_size",
// "tx_size", "cq_size", and "batch_size" fields. If no queues are specified,
// all available queues are auto-detected from sysfs.
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
	opts, err := parseOptions(options)
	if err != nil {
		return nil, serrors.Wrap("parsing options", err)
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	u.applyPreferences(opts)

	if l := u.allLinks[remoteAddr]; l != nil {
		return l, nil
	}
	rxConns, txConns, err := u.getUdpConnections(
		qSize, &localAddr, opts.RxQueues, opts.TxQueues, metrics,
	)
	if err != nil {
		return nil, err
	}
	l := newPtpLinkSibling(&localAddr, &remoteAddr, rxConns, txConns, bfd, metrics)
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
	q0 := []uint32{0}
	rxConns, txConns, err := u.getUdpConnections(
		qSize, &localAddr, q0, q0, metrics,
	)
	if err != nil {
		return nil, err
	}

	il := newInternalLink(
		&localAddr, rxConns, txConns, u.svc,
		u.dispatchStart, u.dispatchEnd, u.dispatchRedirect, metrics,
	)
	u.allLinks[netip.AddrPort{}] = il
	return il, nil
}
