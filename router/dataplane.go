// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
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

package router

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/processmetrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/spao"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/scionproto/scion/private/topology"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
)

const (
	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	bufSize = 9000

	// hopFieldDefaultExpTime is the default validity of the hop field
	// and 63 is equivalent to 6h.
	hopFieldDefaultExpTime = 63

	// e2eAuthHdrLen is the length in bytes of added information when a SCMP packet
	// needs to be authenticated: 16B (e2e.option.Len()) + 16B (CMAC_tag.Len()).
	e2eAuthHdrLen = 32

	// Needed to compute required padding
	ptrSize = unsafe.Sizeof(&struct{ int }{})
	is32bit = 1 - (ptrSize-4)/4
)

type bfdSession interface {
	Run(ctx context.Context) error
	ReceiveMessage(*layers.BFD)
	IsUp() bool
}

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages) (int, error)
	WriteTo([]byte, netip.AddrPort) (int, error)
	WriteBatch(msgs underlayconn.Messages, flags int) (int, error)
	Close() error
}

type disposition int

const (
	pDiscard disposition = iota // Zero value, default.
	pForward
	pSlowPath
	pDone
)

// packet aggregates buffers and ancillary metadata related to one packet.
// That is everything we need to pass-around while processing a packet. The motivation is to save on
// copy (pass everything via one reference) AND garbage collection (reuse everything).
// The buffer is allocated in a separate location (but still reused) to keep the packet structures
// tightly packed (might not matter, though).
// Golang gives precious little guarantees about alignment and padding. We do it ourselves in such
// a way that Go has no sane reason to add any padding. Everything is 8 byte aligned (on 64 bit
// arch) until Slowpath request which is 6 bytes long. The rest is in decreasing order of size and
// size-aligned. We want to fit neatly into cache lines, so we need to fit in 64 bytes. The padding
// required to occupy exactly 64 bytes depends on the architecture.
type packet struct {
	// The useful part of the raw packet at a point in time (i.e. a slice of the full buffer).
	// TODO(jiceatscion): would it be beneficial to store the length instead, like readBatch does?
	rawPacket []byte
	// The source address. Will be set by the receiver from smsg.Addr. We could update it in-place,
	// but the IP address bytes in it are allocated by readbatch, so if we copy into a recyclable
	// location, it's the original we throw away. No gain (may be a tiny bit?).
	srcAddr *net.UDPAddr
	// The address to where we are forwarding the packet.
	// Will be set by the processing routine; it is updated in-place.
	dstAddr *net.UDPAddr
	// Additional metadata in case the packet is put on the slow path. Updated in-place.
	slowPathRequest slowPathRequest
	// The ingress on which this packet arrived. This is set by the receiver.
	ingress uint16
	// The egress on which this packet must leave. This is set by the processing routine.
	egress uint16
	// The type of traffic. This is used for metrics at the forwarding stage, but is most
	// economically determined at the processing stage. So store it here. It's 2 bytes long.
	trafficType trafficType
	// Pad to 64 bytes. For 64bit arch, add 12 bytes. For 32bit arch, add 32 bytes.
	// TODO(jiceatscion): see if packing two packets per cache line instead is good or bad for 32bit
	// machines.
	_ [12 + is32bit*20]byte
}

// Keep this 6 bytes long. See comment for packet.
type slowPathRequest struct {
	pointer  uint16
	typ      slowPathType
	scmpType slayers.SCMPType
	code     slayers.SCMPCode
	_        uint8
}

// Make sure that the packet structure has the size we expect.
const _ uintptr = 64 - unsafe.Sizeof(packet{}) // assert 64 >= sizeof(packet)
const _ uintptr = unsafe.Sizeof(packet{}) - 64 // assert sizeof(packet) >= 64

// initPacket configures the given blank packet (and returns it, for convenience).
func (p *packet) init(buffer *[bufSize]byte) *packet {
	p.rawPacket = buffer[:]
	p.dstAddr = &net.UDPAddr{IP: make(net.IP, net.IPv6len)}
	return p
}

// reset() makes the packet ready to receive a new underlay message.
// A cleared dstAddr is represented with a zero-length IP so we keep reusing the IP storage bytes.
func (p *packet) reset() {
	p.dstAddr.IP = p.dstAddr.IP[0:0] // We're keeping the object, just blank it.
	*p = packet{
		rawPacket: p.rawPacket[:cap(p.rawPacket)], // keep the slice and so the backing array.
		dstAddr:   p.dstAddr,                      // keep the dstAddr and so the IP slice and bytes
	}
	// Everything else is reset to zero value.

}

// DataPlane contains a SCION Border Router's forwarding logic. It reads packets
// from multiple sockets, performs routing, and sends them to their destinations
// (after updating the path, if that is needed).
type DataPlane struct {
	interfaces          map[uint16]BatchConn
	external            map[uint16]BatchConn
	linkTypes           map[uint16]topology.LinkType
	neighborIAs         map[uint16]addr.IA
	peerInterfaces      map[uint16]uint16
	internal            BatchConn
	internalIP          netip.Addr
	internalNextHops    map[uint16]netip.AddrPort
	svc                 *services
	macFactory          func() hash.Hash
	bfdSessions         map[uint16]bfdSession
	localIA             addr.IA
	mtx                 sync.Mutex
	running             atomic.Bool
	Metrics             *Metrics
	forwardingMetrics   map[uint16]interfaceMetrics
	dispatchedPortStart uint16
	dispatchedPortEnd   uint16

	ExperimentalSCMPAuthentication bool

	// The pool that stores all the packet buffers as described in the design document. See
	// https://github.com/scionproto/scion/blob/master/doc/dev/design/BorderRouter.rst
	// To avoid garbage collection, most the meta-data that is produced during the processing of a
	// packet is kept in a data structure (packet struct) that is pooled and recycled along with
	// corresponding packet buffer. The packet struct refers permanently to the packet buffer. The
	// packet structure is fetched from the pool passed-around through the various channels and
	// returned to the pool. To reduce the cost of copying, the packet structure is passed by
	// reference.
	packetPool chan *packet
}

var (
	alreadySet                    = errors.New("already set")
	invalidSrcIA                  = errors.New("invalid source ISD-AS")
	invalidDstIA                  = errors.New("invalid destination ISD-AS")
	invalidSrcAddrForTransit      = errors.New("invalid source address for transit pkt")
	invalidDstAddr                = errors.New("invalid destination address")
	cannotRoute                   = errors.New("cannot route, dropping pkt")
	emptyValue                    = errors.New("empty value")
	malformedPath                 = errors.New("malformed path content")
	modifyExisting                = errors.New("modifying a running dataplane is not allowed")
	noSVCBackend                  = errors.New("cannot find internal IP for the SVC")
	unsupportedPathType           = errors.New("unsupported path type")
	unsupportedPathTypeNextHeader = errors.New("unsupported combination")
	unsupportedV4MappedV6Address  = errors.New("unsupported v4mapped IP v6 address")
	unsupportedUnspecifiedAddress = errors.New("unsupported unspecified address")
	noBFDSessionFound             = errors.New("no BFD session was found")
	noBFDSessionConfigured        = errors.New("no BFD sessions have been configured")
	errPeeringEmptySeg0           = errors.New("zero-length segment[0] in peering path")
	errPeeringEmptySeg1           = errors.New("zero-length segment[1] in peering path")
	errPeeringNonemptySeg2        = errors.New("non-zero-length segment[2] in peering path")
	errShortPacket                = errors.New("Packet is too short")
	errBFDSessionDown             = errors.New("bfd session down")
	expiredHop                    = errors.New("expired hop")
	ingressInterfaceInvalid       = errors.New("ingress interface invalid")
	macVerificationFailed         = errors.New("MAC verification failed")
	badPacketSize                 = errors.New("bad packet size")

	// zeroBuffer will be used to reset the Authenticator option in the
	// scionPacketProcessor.OptAuth
	zeroBuffer = make([]byte, 16)
)

type drkeyProvider interface {
	GetASHostKey(validTime time.Time, dstIA addr.IA, dstAddr addr.Host) (drkey.ASHostKey, error)
	GetKeyWithinAcceptanceWindow(
		validTime time.Time,
		timestamp uint64,
		dstIA addr.IA,
		dstAddr addr.Host,
	) (drkey.ASHostKey, error)
}

// setRunning() Configures the running state of the data plane to true. setRunning() is called once
// the dataplane is finished initializing and is ready to process packets.
func (d *DataPlane) setRunning() {
	d.running.Store(true)
}

// setStopping() Configures the running state of the data plane to false. This should not be called
// during the dataplane initialization. Calling this before initialization starts has no effect.
func (d *DataPlane) setStopping() {
	d.running.Store(false)
}

// IsRunning() Indicates the running state of the data plane. If true, the dataplane is initialized
// and ready to process or already processing packets. In this case some configuration changes are
// not permitted. If false, the data plane is not ready to process packets yet, or is shutting
// down.
func (d *DataPlane) IsRunning() bool {
	return d.running.Load()
}

// Shutdown() causes the dataplane to stop accepting packets and then terminate. Note that
// in that case the router is committed to shutting down. There is no mechanism to restart it.
func (d *DataPlane) Shutdown() {
	d.mtx.Lock() // make sure we're nor racing with initialization.
	defer d.mtx.Unlock()
	d.setStopping()
}

// SetIA sets the local IA for the dataplane.
func (d *DataPlane) SetIA(ia addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.IsRunning() {
		return modifyExisting
	}
	if ia.IsZero() {
		return emptyValue
	}
	if !d.localIA.IsZero() {
		return alreadySet
	}
	d.localIA = ia
	return nil
}

// SetKey sets the key used for MAC verification. The key provided here should
// already be derived as in scrypto.HFMacFactory.
func (d *DataPlane) SetKey(key []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.IsRunning() {
		return modifyExisting
	}
	if len(key) == 0 {
		return emptyValue
	}
	if d.macFactory != nil {
		return alreadySet
	}
	// First check for MAC creation errors.
	if _, err := scrypto.InitMac(key); err != nil {
		return err
	}
	d.macFactory = func() hash.Hash {
		mac, _ := scrypto.InitMac(key)
		return mac
	}
	return nil
}

func (d *DataPlane) SetPortRange(start, end uint16) {
	d.dispatchedPortStart = start
	d.dispatchedPortEnd = end
}

// AddInternalInterface sets the interface the data-plane will use to
// send/receive traffic in the local AS. This can only be called once; future
// calls will return an error. This can only be called on a not yet running
// dataplane.
func (d *DataPlane) AddInternalInterface(conn BatchConn, ip netip.Addr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.IsRunning() {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	if d.internal != nil {
		return alreadySet
	}
	if d.interfaces == nil {
		d.interfaces = make(map[uint16]BatchConn)
	}
	d.interfaces[0] = conn
	d.internal = conn
	d.internalIP = ip
	return nil
}

// AddExternalInterface adds the inter AS connection for the given interface ID.
// If a connection for the given ID is already set this method will return an
// error. This can only be called on a not yet running dataplane.
func (d *DataPlane) AddExternalInterface(ifID uint16, conn BatchConn,
	src, dst control.LinkEnd, cfg control.BFD) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.IsRunning() {
		return modifyExisting
	}
	if conn == nil || !src.Addr.IsValid() || !dst.Addr.IsValid() {
		return emptyValue
	}
	err := d.addExternalInterfaceBFD(ifID, conn, src, dst, cfg)
	if err != nil {
		return serrors.WrapStr("adding external BFD", err, "if_id", ifID)
	}
	if d.external == nil {
		d.external = make(map[uint16]BatchConn)
	}
	if d.interfaces == nil {
		d.interfaces = make(map[uint16]BatchConn)
	}
	if _, exists := d.external[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	d.interfaces[ifID] = conn
	d.external[ifID] = conn
	return nil
}

// AddNeighborIA adds the neighboring IA for a given interface ID. If an IA for
// the given ID is already set, this method will return an error. This can only
// be called on a yet running dataplane.
func (d *DataPlane) AddNeighborIA(ifID uint16, remote addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.IsRunning() {
		return modifyExisting
	}
	if remote.IsZero() {
		return emptyValue
	}
	if _, exists := d.neighborIAs[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.neighborIAs == nil {
		d.neighborIAs = make(map[uint16]addr.IA)
	}
	d.neighborIAs[ifID] = remote
	return nil
}

// AddLinkType adds the link type for a given interface ID. If a link type for
// the given ID is already set, this method will return an error. This can only
// be called on a not yet running dataplane.
func (d *DataPlane) AddLinkType(ifID uint16, linkTo topology.LinkType) error {
	if _, exists := d.linkTypes[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.linkTypes == nil {
		d.linkTypes = make(map[uint16]topology.LinkType)
	}
	d.linkTypes[ifID] = linkTo
	return nil
}

// AddRemotePeer adds the remote peering interface ID for local
// interface ID.  If the link type for the given ID is already set to
// a different type, this method will return an error. This can only
// be called on a not yet running dataplane.
func (d *DataPlane) AddRemotePeer(local, remote uint16) error {
	if t, ok := d.linkTypes[local]; ok && t != topology.Peer {
		return serrors.WithCtx(unsupportedPathType, "type", t)
	}
	if _, exists := d.peerInterfaces[local]; exists {
		return serrors.WithCtx(alreadySet, "local_interface", local)
	}
	if d.peerInterfaces == nil {
		d.peerInterfaces = make(map[uint16]uint16)
	}
	d.peerInterfaces[local] = remote
	return nil
}

// AddExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *DataPlane) addExternalInterfaceBFD(ifID uint16, conn BatchConn,
	src, dst control.LinkEnd, cfg control.BFD) error {

	if *cfg.Disable {
		return nil
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{
			"interface":       fmt.Sprint(ifID),
			"isd_as":          d.localIA.String(),
			"neighbor_isd_as": dst.IA.String(),
		}
		m = bfd.Metrics{
			Up:              d.Metrics.InterfaceUp.With(labels),
			StateChanges:    d.Metrics.BFDInterfaceStateChanges.With(labels),
			PacketsSent:     d.Metrics.BFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.BFDPacketsReceived.With(labels),
		}
	}
	s, err := newBFDSend(conn, src.IA, dst.IA, src.Addr, dst.Addr, ifID, d.macFactory())
	if err != nil {
		return err
	}
	return d.addBFDController(ifID, s, cfg, m)
}

// getInterfaceState checks if there is a bfd session for the input interfaceID and
// returns InterfaceUp if the relevant bfdsession state is up, or if there is no BFD
// session. Otherwise, it returns InterfaceDown.
func (d *DataPlane) getInterfaceState(ifID uint16) control.InterfaceState {
	bfdSessions := d.bfdSessions
	if bfdSession, ok := bfdSessions[ifID]; ok && !bfdSession.IsUp() {
		return control.InterfaceDown
	}
	return control.InterfaceUp
}

func (d *DataPlane) addBFDController(ifID uint16, s *bfdSend, cfg control.BFD,
	metrics bfd.Metrics) error {

	if d.bfdSessions == nil {
		d.bfdSessions = make(map[uint16]bfdSession)
	}

	// Generate random discriminator. It can't be zero.
	discInt, err := rand.Int(rand.Reader, big.NewInt(0xfffffffe))
	if err != nil {
		return err
	}
	disc := layers.BFDDiscriminator(uint32(discInt.Uint64()) + 1)
	d.bfdSessions[ifID] = &bfd.Session{
		Sender:                s,
		DetectMult:            layers.BFDDetectMultiplier(cfg.DetectMult),
		DesiredMinTxInterval:  cfg.DesiredMinTxInterval,
		RequiredMinRxInterval: cfg.RequiredMinRxInterval,
		LocalDiscriminator:    disc,
		ReceiveQueueSize:      10,
		Metrics:               metrics,
	}
	return nil
}

// AddSvc adds the address for the given service. This can be called multiple
// times for the same service, with the address added to the list of addresses
// that provide the service.
func (d *DataPlane) AddSvc(svc addr.SVC, a netip.AddrPort) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if !a.IsValid() {
		return emptyValue
	}
	if d.svc == nil {
		d.svc = newServices()
	}
	d.svc.AddSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(1)
	}
	return nil
}

// DelSvc deletes the address for the given service.
func (d *DataPlane) DelSvc(svc addr.SVC, a netip.AddrPort) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if !a.IsValid() {
		return emptyValue
	}
	if d.svc == nil {
		return nil
	}
	d.svc.DelSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(-1)
	}
	return nil
}

// AddNextHop sets the next hop address for the given interface ID. If the
// interface ID already has an address associated this operation fails. This can
// only be called on a not yet running dataplane.
func (d *DataPlane) AddNextHop(ifID uint16, src, dst netip.AddrPort, cfg control.BFD,
	sibling string) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.IsRunning() {
		return modifyExisting
	}
	if !dst.IsValid() || !src.IsValid() {
		return emptyValue
	}
	err := d.addNextHopBFD(ifID, src, dst, cfg, sibling)
	if err != nil {
		return serrors.WrapStr("adding next hop BFD", err, "if_id", ifID)
	}
	if d.internalNextHops == nil {
		d.internalNextHops = make(map[uint16]netip.AddrPort)
	}
	if _, exists := d.internalNextHops[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	d.internalNextHops[ifID] = dst
	return nil
}

// AddNextHopBFD adds the BFD session for the next hop address.
// If the remote ifID belongs to an existing address, the existing
// BFD session will be re-used.
func (d *DataPlane) addNextHopBFD(ifID uint16, src, dst netip.AddrPort, cfg control.BFD,
	sibling string) error {

	if *cfg.Disable {
		return nil
	}
	for k, v := range d.internalNextHops {
		if v.String() == dst.String() {
			if c, ok := d.bfdSessions[k]; ok {
				d.bfdSessions[ifID] = c
				return nil
			}
		}
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{"isd_as": d.localIA.String(), "sibling": sibling}
		m = bfd.Metrics{
			Up:              d.Metrics.SiblingReachable.With(labels),
			StateChanges:    d.Metrics.SiblingBFDStateChanges.With(labels),
			PacketsSent:     d.Metrics.SiblingBFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.SiblingBFDPacketsReceived.With(labels),
		}
	}

	s, err := newBFDSend(d.internal, d.localIA, d.localIA, src, dst, 0, d.macFactory())
	if err != nil {
		return err
	}
	return d.addBFDController(ifID, s, cfg, m)
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

type RunConfig struct {
	NumProcessors         int
	NumSlowPathProcessors int
	BatchSize             int
}

func (d *DataPlane) Run(ctx context.Context, cfg *RunConfig) error {
	d.mtx.Lock()
	d.setRunning()
	d.initMetrics()

	processorQueueSize := max(
		len(d.interfaces)*cfg.BatchSize/cfg.NumProcessors,
		cfg.BatchSize)

	d.initPacketPool(cfg, processorQueueSize)
	procQs, fwQs, slowQs := initQueues(cfg, d.interfaces, processorQueueSize)

	for ifID, conn := range d.interfaces {
		go func(ifID uint16, conn BatchConn) {
			defer log.HandlePanic()
			d.runReceiver(ifID, conn, cfg, procQs)
		}(ifID, conn)
		go func(ifID uint16, conn BatchConn) {
			defer log.HandlePanic()
			d.runForwarder(ifID, conn, cfg, fwQs[ifID])
		}(ifID, conn)
	}
	for i := 0; i < cfg.NumProcessors; i++ {
		go func(i int) {
			defer log.HandlePanic()
			d.runProcessor(i, procQs[i], fwQs, slowQs[i%cfg.NumSlowPathProcessors])
		}(i)
	}
	for i := 0; i < cfg.NumSlowPathProcessors; i++ {
		go func(i int) {
			defer log.HandlePanic()
			d.runSlowPathProcessor(i, slowQs[i], fwQs)
		}(i)
	}

	for k, v := range d.bfdSessions {
		go func(ifID uint16, c bfdSession) {
			defer log.HandlePanic()
			if err := c.Run(ctx); err != nil && err != bfd.AlreadyRunning {
				log.Error("BFD session failed to start", "ifID", ifID, "err", err)
			}
		}(k, v)
	}

	d.mtx.Unlock()
	<-ctx.Done()
	return nil
}

// initializePacketPool calculates the size of the packet pool based on the
// current dataplane settings and allocates all the buffers
func (d *DataPlane) initPacketPool(cfg *RunConfig, processorQueueSize int) {
	poolSize := len(d.interfaces)*cfg.BatchSize +
		(cfg.NumProcessors+cfg.NumSlowPathProcessors)*(processorQueueSize+1) +
		len(d.interfaces)*(2*cfg.BatchSize)

	log.Debug("Initialize packet pool of size", "poolSize", poolSize)
	d.packetPool = make(chan *packet, poolSize)
	pktBuffers := make([][bufSize]byte, poolSize)
	pktStructs := make([]packet, poolSize)
	for i := 0; i < poolSize; i++ {
		d.packetPool <- pktStructs[i].init(&pktBuffers[i])
	}
}

// initializes the processing routines and forwarders queues
func initQueues(cfg *RunConfig, interfaces map[uint16]BatchConn,
	processorQueueSize int) ([]chan *packet, map[uint16]chan *packet, []chan *packet) {

	procQs := make([]chan *packet, cfg.NumProcessors)
	for i := 0; i < cfg.NumProcessors; i++ {
		procQs[i] = make(chan *packet, processorQueueSize)
	}
	slowQs := make([]chan *packet, cfg.NumSlowPathProcessors)
	for i := 0; i < cfg.NumSlowPathProcessors; i++ {
		slowQs[i] = make(chan *packet, processorQueueSize)
	}
	fwQs := make(map[uint16]chan *packet)
	for ifID := range interfaces {
		fwQs[ifID] = make(chan *packet, cfg.BatchSize)
	}
	return procQs, fwQs, slowQs
}

func (d *DataPlane) runReceiver(ifID uint16, conn BatchConn, cfg *RunConfig,
	procQs []chan *packet) {

	log.Debug("Run receiver for", "interface", ifID)

	// Each receiver (therefore each input interface) has a unique random seed for the procID hash
	// function.
	hashSeed := fnv1aOffset32
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		panic("Error while generating random value")
	}
	for _, c := range randomBytes {
		hashSeed = hashFNV1a(hashSeed, c)
	}

	// A collection of socket messages, as the readBatch API expects them. We keep using the same
	// collection, call after call; only replacing the buffer.
	msgs := underlayconn.NewReadMessages(cfg.BatchSize)

	// An array of corresponding packet references. Each corresponds to one msg.
	// The packet owns the buffer that we set in the matching msg, plus the metadata that we'll add.
	packets := make([]*packet, cfg.BatchSize)

	numReusable := 0                     // unused buffers from previous loop
	metrics := d.forwardingMetrics[ifID] // If receiver exists, fw metrics exist too.

	enqueueForProcessing := func(size int, srcAddr *net.UDPAddr, pkt *packet) {
		sc := classOfSize(size)
		metrics[sc].InputPacketsTotal.Inc()
		metrics[sc].InputBytesTotal.Add(float64(size))

		procID, err := computeProcID(pkt.rawPacket, cfg.NumProcessors, hashSeed)
		if err != nil {
			log.Debug("Error while computing procID", "err", err)
			d.returnPacketToPool(pkt)
			metrics[sc].DroppedPacketsInvalid.Inc()
			return
		}

		pkt.rawPacket = pkt.rawPacket[:size] // Update size; readBatch does not.
		pkt.ingress = ifID
		pkt.srcAddr = srcAddr
		select {
		case procQs[procID] <- pkt:
		default:
			d.returnPacketToPool(pkt)
			metrics[sc].DroppedPacketsBusyProcessor.Inc()
		}
	}

	for d.IsRunning() {
		// collect packets.

		// Give a new buffer to the msgs elements that have been used in the previous loop.
		for i := 0; i < cfg.BatchSize-numReusable; i++ {
			p := <-d.packetPool
			p.reset()
			packets[i] = p
			msgs[i].Buffers[0] = p.rawPacket
		}

		// Fill the packets
		numPkts, err := conn.ReadBatch(msgs)
		numReusable = len(msgs) - numPkts
		if err != nil {
			log.Debug("Error while reading batch", "interfaceID", ifID, "err", err)
			continue
		}
		for i, msg := range msgs[:numPkts] {
			enqueueForProcessing(msg.N, msg.Addr.(*net.UDPAddr), packets[i])
		}
	}
}

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

func (d *DataPlane) returnPacketToPool(pkt *packet) {
	d.packetPool <- pkt
}

func (d *DataPlane) runProcessor(id int, q <-chan *packet,
	fwQs map[uint16]chan *packet, slowQ chan<- *packet) {

	log.Debug("Initialize processor with", "id", id)
	processor := newPacketProcessor(d)
	for d.IsRunning() {
		p, ok := <-q
		if !ok {
			continue
		}
		disp := processor.processPkt(p)

		sc := classOfSize(len(p.rawPacket))
		metrics := d.forwardingMetrics[p.ingress][sc]
		metrics.ProcessedPackets.Inc()

		switch disp {
		case pForward:
			// Normal processing proceeds.
		case pSlowPath:
			// Not an error, processing continues on the slow path.
			select {
			case slowQ <- p:
			default:
				metrics.DroppedPacketsBusySlowPath.Inc()
				d.returnPacketToPool(p)
			}
			continue
		case pDone: // Packets that don't need more processing (e.g. BFD)
			d.returnPacketToPool(p)
			continue
		case pDiscard: // Everything else
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(p)
			continue
		default: // Newly added dispositions need to be handled.
			log.Debug("Unknown packet disposition", "disp", disp)
			d.returnPacketToPool(p)
			continue
		}
		fwCh, ok := fwQs[p.egress]
		if !ok {
			log.Debug("Error determining forwarder. Egress is invalid", "egress", p.egress)
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(p)
			continue
		}

		select {
		case fwCh <- p:
		default:
			d.returnPacketToPool(p)
			metrics.DroppedPacketsBusyForwarder.Inc()
		}
	}
}

func (d *DataPlane) runSlowPathProcessor(id int, q <-chan *packet,
	fwQs map[uint16]chan *packet) {

	log.Debug("Initialize slow-path processor with", "id", id)
	processor := newSlowPathProcessor(d)
	for d.IsRunning() {
		p, ok := <-q
		if !ok {
			continue
		}
		err := processor.processPacket(p)
		sc := classOfSize(len(p.rawPacket))
		metrics := d.forwardingMetrics[p.ingress][sc]
		if err != nil {
			log.Debug("Error processing packet", "err", err)
			metrics.DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(p)
			continue
		}
		fwCh, ok := fwQs[p.egress]
		if !ok {
			log.Debug("Error determining forwarder. Egress is invalid", "egress", p.egress)
			d.returnPacketToPool(p)
			continue
		}
		select {
		case fwCh <- p:
		default:
			d.returnPacketToPool(p)
		}
	}
}

func newSlowPathProcessor(d *DataPlane) *slowPathPacketProcessor {
	p := &slowPathPacketProcessor{
		d:              d,
		buffer:         gopacket.NewSerializeBuffer(),
		macInputBuffer: make([]byte, spao.MACBufferSize),
		drkeyProvider: &drkeyutil.FakeProvider{
			EpochDuration:    drkeyutil.LoadEpochDuration(),
			AcceptanceWindow: drkeyutil.LoadAcceptanceWindow(),
		},
		optAuth:      slayers.PacketAuthOption{EndToEndOption: new(slayers.EndToEndOption)},
		validAuthBuf: make([]byte, 16),
	}
	p.scionLayer.RecyclePaths()
	return p
}

type slowPathPacketProcessor struct {
	d      *DataPlane
	pkt    *packet
	buffer gopacket.SerializeBuffer

	scionLayer slayers.SCION
	hbhLayer   slayers.HopByHopExtnSkipper
	e2eLayer   slayers.EndToEndExtnSkipper
	lastLayer  gopacket.DecodingLayer
	path       *scion.Raw

	// macInputBuffer avoid allocating memory during processing.
	macInputBuffer []byte

	// optAuth is a reusable Packet Authenticator Option
	optAuth slayers.PacketAuthOption
	// validAuthBuf is a reusable buffer for the authentication tag
	// to be used in the hasValidAuth() method.
	validAuthBuf []byte

	// DRKey key derivation for SCMP authentication
	drkeyProvider drkeyProvider
}

func (p *slowPathPacketProcessor) reset() {
	if err := p.buffer.Clear(); err != nil {
		// The serializeBuffer returned by NewSerializeBuffer isn't actually capable of failing to
		// clear, so planning on doing something about it is pointless (and what might that be?).
		panic(fmt.Sprintf("Error while clearing buffer: %v", err))
	}
	p.path = nil
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
}

func (p *slowPathPacketProcessor) processPacket(pkt *packet) error {
	var err error
	p.reset()
	p.pkt = pkt

	p.lastLayer, err = decodeLayers(pkt.rawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return err
	}
	pathType := p.scionLayer.PathType
	switch pathType {
	case scion.PathType:
		var ok bool
		p.path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return malformedPath
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return malformedPath
		}
		p.path = epicPath.ScionPath
		if p.path == nil {
			return malformedPath
		}
	default:
		//unsupported path type
		return serrors.New("Path type not supported for slow-path", "type", pathType)
	}

	s := pkt.slowPathRequest
	switch s.typ {
	case slowPathSCMP: //SCMP
		var layer gopacket.SerializableLayer
		switch s.scmpType {
		case slayers.SCMPTypeParameterProblem:
			layer = &slayers.SCMPParameterProblem{Pointer: s.pointer}
		case slayers.SCMPTypeDestinationUnreachable:
			layer = &slayers.SCMPDestinationUnreachable{}
		case slayers.SCMPTypeExternalInterfaceDown:
			layer = &slayers.SCMPExternalInterfaceDown{IA: p.d.localIA,
				IfID: uint64(p.pkt.egress)}
		case slayers.SCMPTypeInternalConnectivityDown:
			layer = &slayers.SCMPInternalConnectivityDown{IA: p.d.localIA,
				Ingress: uint64(p.pkt.ingress), Egress: uint64(p.pkt.egress)}
		}
		return p.packSCMP(s.scmpType, s.code, layer, true)

	case slowPathRouterAlertIngress: //Traceroute
		return p.handleSCMPTraceRouteRequest(p.pkt.ingress)
	case slowPathRouterAlertEgress: //Traceroute
		return p.handleSCMPTraceRouteRequest(p.pkt.egress)
	default:
		panic("Unsupported slow-path type")
	}
}

func updateOutputMetrics(metrics interfaceMetrics, packets []*packet) {
	// We need to collect stats by traffic type and size class.
	// Try to reduce the metrics lookup penalty by using some
	// simpler staging data structure.
	writtenPkts := [ttMax][maxSizeClass]int{}
	writtenBytes := [ttMax][maxSizeClass]int{}
	for _, p := range packets {
		s := len(p.rawPacket)
		sc := classOfSize(s)
		tt := p.trafficType
		writtenPkts[tt][sc]++
		writtenBytes[tt][sc] += s
	}
	for t := ttOther; t < ttMax; t++ {
		for sc := minSizeClass; sc < maxSizeClass; sc++ {
			if writtenPkts[t][sc] > 0 {
				metrics[sc].Output[t].OutputPacketsTotal.Add(float64(writtenPkts[t][sc]))
				metrics[sc].Output[t].OutputBytesTotal.Add(float64(writtenBytes[t][sc]))
			}
		}
	}
}

func (d *DataPlane) runForwarder(ifID uint16, conn BatchConn, cfg *RunConfig, c <-chan *packet) {

	log.Debug("Initialize forwarder for", "interface", ifID)

	// We use this somewhat like a ring buffer.
	pkts := make([]*packet, cfg.BatchSize)

	// We use this as a temporary buffer, but allocate it just once
	// to save on garbage handling.
	msgs := make(underlayconn.Messages, cfg.BatchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
	}

	metrics := d.forwardingMetrics[ifID]

	toWrite := 0
	for d.IsRunning() {
		toWrite += readUpTo(c, cfg.BatchSize-toWrite, toWrite == 0, pkts[toWrite:])

		// Turn the packets into underlay messages that WriteBatch can send.
		for i, p := range pkts[:toWrite] {
			msgs[i].Buffers[0] = p.rawPacket
			msgs[i].Addr = nil
			if len(p.dstAddr.IP) != 0 {
				msgs[i].Addr = p.dstAddr
			}
		}
		written, _ := conn.WriteBatch(msgs[:toWrite], 0)
		if written < 0 {
			// WriteBatch returns -1 on error, we just consider this as
			// 0 packets written
			written = 0
		}

		updateOutputMetrics(metrics, pkts[:written])

		for _, p := range pkts[:written] {
			d.returnPacketToPool(p)
		}

		if written != toWrite {
			// Only one is dropped at this time. We'll retry the rest.
			sc := classOfSize(len(pkts[written].rawPacket))
			metrics[sc].DroppedPacketsInvalid.Inc()
			d.returnPacketToPool(pkts[written])
			toWrite -= (written + 1)
			// Shift the leftovers to the head of the buffers.
			for i := 0; i < toWrite; i++ {
				pkts[i] = pkts[i+written+1]
			}

		} else {
			toWrite = 0
		}
	}
}

func readUpTo(c <-chan *packet, n int, needsBlocking bool, pkts []*packet) int {
	i := 0
	if needsBlocking {
		p, ok := <-c
		if !ok {
			return i
		}
		pkts[i] = p
		i++
	}

	for ; i < n; i++ {
		select {
		case p, ok := <-c:
			if !ok {
				return i
			}
			pkts[i] = p
		default:
			return i
		}

	}
	return i
}

func newPacketProcessor(d *DataPlane) *scionPacketProcessor {
	p := &scionPacketProcessor{
		d:              d,
		buffer:         gopacket.NewSerializeBuffer(),
		mac:            d.macFactory(),
		macInputBuffer: make([]byte, max(path.MACBufferSize, libepic.MACBufferSize)),
	}
	p.scionLayer.RecyclePaths()
	return p
}

func (p *scionPacketProcessor) reset() error {
	p.pkt = nil
	//p.scionLayer // cannot easily be reset
	p.path = nil
	p.hopField = path.HopField{}
	p.infoField = path.InfoField{}
	p.effectiveXover = false
	p.peering = false
	if err := p.buffer.Clear(); err != nil {
		// The serializeBuffer returned by NewSerializeBuffer isn't actually capable of failing to
		// clear, so planning on doing something about it is pointless (and what might that be?).
		panic(fmt.Sprintf("Error while clearing buffer: %v", err))
	}
	p.mac.Reset()
	p.cachedMac = nil
	// Reset hbh layer
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	// Reset e2e layer
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
	return nil
}

// Convenience function to log an error and return the pDiscard disposition.
// We do almost nothing with errors, so, we shouldn't invest in creating them.
func errorDiscard(ctx ...any) disposition {
	log.Debug("Discarding packet", ctx...)
	return pDiscard
}

func (p *scionPacketProcessor) processPkt(pkt *packet) disposition {
	if err := p.reset(); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt = pkt

	// parse SCION header and skip extensions;
	var err error
	p.lastLayer, err = decodeLayers(pkt.rawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	pld := p.lastLayer.LayerPayload()

	pathType := p.scionLayer.PathType
	switch pathType {
	case empty.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			return p.processIntraBFD(pld)
		}
		return errorDiscard("error", unsupportedPathTypeNextHeader)

	case onehop.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			ohp, ok := p.scionLayer.Path.(*onehop.Path)
			if !ok {
				return errorDiscard("error", malformedPath)
			}
			return p.processInterBFD(ohp, pld)
		}
		return p.processOHP()
	case scion.PathType:
		return p.processSCION()
	case epic.PathType:
		return p.processEPIC()
	default:
		return errorDiscard("error", unsupportedPathType)
	}
}

func (p *scionPacketProcessor) processInterBFD(oh *onehop.Path, data []byte) disposition {
	if len(p.d.bfdSessions) == 0 {
		return errorDiscard("error", noBFDSessionConfigured)
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return errorDiscard("error", err)
	}

	if v, ok := p.d.bfdSessions[p.pkt.ingress]; ok {
		v.ReceiveMessage(bfd)
		return pDiscard // All's fine. That packet's journey ends here.
	}

	return errorDiscard("error", noBFDSessionFound)
}

func (p *scionPacketProcessor) processIntraBFD(data []byte) disposition {
	if len(p.d.bfdSessions) == 0 {
		return errorDiscard("error", noBFDSessionConfigured)
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return errorDiscard("error", err)
	}

	ifID := uint16(0)
	src := p.pkt.srcAddr.AddrPort() // POSSIBLY EXPENSIVE CONVERSION
	for k, v := range p.d.internalNextHops {
		if src == v {
			ifID = k
			break
		}
	}

	if v, ok := p.d.bfdSessions[ifID]; ok {
		v.ReceiveMessage(bfd)
		return pDiscard // All's fine. That packet's journey ends here.
	}

	return errorDiscard("error", noBFDSessionFound)
}

func (p *scionPacketProcessor) processSCION() disposition {

	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", malformedPath)
	}
	return p.process()
}

func (p *scionPacketProcessor) processEPIC() disposition {

	epicPath, ok := p.scionLayer.Path.(*epic.Path)
	if !ok {
		return errorDiscard("error", malformedPath)
	}

	p.path = epicPath.ScionPath
	if p.path == nil {
		return errorDiscard("error", malformedPath)
	}

	isPenultimate := p.path.IsPenultimateHop()
	isLast := p.path.IsLastHop()

	disp := p.process()
	if disp != pForward {
		return disp
	}

	if isPenultimate || isLast {
		firstInfo, err := p.path.GetInfoField(0)
		if err != nil {
			return errorDiscard("error", err)
		}

		timestamp := time.Unix(int64(firstInfo.Timestamp), 0)
		err = libepic.VerifyTimestamp(timestamp, epicPath.PktID.Timestamp, time.Now())
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return errorDiscard("error", err)
		}

		HVF := epicPath.PHVF
		if isLast {
			HVF = epicPath.LHVF
		}
		err = libepic.VerifyHVF(p.cachedMac, epicPath.PktID,
			&p.scionLayer, firstInfo.Timestamp, HVF, p.macInputBuffer[:libepic.MACBufferSize])
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return errorDiscard("error", err)
		}
	}

	// LGTM
	return pForward
}

// scionPacketProcessor processes packets. It contains pre-allocated per-packet
// mutable state and context information which should be reused.
type scionPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// pkt is the packet currently being processed by this processor.
	pkt *packet
	// buffer is the buffer that can be used to serialize gopacket layers.
	buffer gopacket.SerializeBuffer
	// mac is the hasher for the MAC computation.
	mac hash.Hash

	// scionLayer is the SCION gopacket layer.
	scionLayer slayers.SCION
	hbhLayer   slayers.HopByHopExtnSkipper
	e2eLayer   slayers.EndToEndExtnSkipper
	// last is the last parsed layer, i.e. either &scionLayer, &hbhLayer or &e2eLayer
	lastLayer gopacket.DecodingLayer

	// path is the raw SCION path. Will be set during processing.
	path *scion.Raw
	// hopField is the current hopField field, is updated during processing.
	hopField path.HopField
	// infoField is the current infoField field, is updated during processing.
	infoField path.InfoField
	// effectiveXover indicates if a cross-over segment change was done during processing.
	effectiveXover bool

	// peering indicates that the hop field being processed is a peering hop field.
	peering bool

	// cachedMac contains the full 16 bytes of the MAC. Will be set during processing.
	// For a hop performing an Xover, it is the MAC corresponding to the down segment.
	cachedMac []byte
	// macInputBuffer avoid allocating memory during processing.
	macInputBuffer []byte

	// bfdLayer is reusable buffer for parsing BFD messages
	bfdLayer layers.BFD
}

type slowPathType uint8

const (
	slowPathSCMP slowPathType = iota
	slowPathRouterAlertIngress
	slowPathRouterAlertEgress
)

func (p *slowPathPacketProcessor) packSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	isError bool,
) error {

	// check invoking packet was an SCMP error:
	if p.lastLayer.NextLayerType() == slayers.LayerTypeSCMP {
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(p.lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return serrors.WrapStr("decoding SCMP layer", err)
		}
		if !scmpLayer.TypeCode.InfoMsg() {
			return serrors.New("SCMP error for SCMP error pkt -> DROP")
		}
	}

	rawSCMP, err := p.prepareSCMP(typ, code, scmpP, isError)
	if rawSCMP != nil {
		p.pkt.rawPacket = p.pkt.rawPacket[:len(rawSCMP)]
		copy(p.pkt.rawPacket, rawSCMP)
	}

	// We're about to send a packet that has little to do with the one we received.
	// The original traffic type, if one had been set, no-longer applies.
	p.pkt.trafficType = ttOther
	p.pkt.egress = p.pkt.ingress
	updateNetAddrFromNetAddr(p.pkt.dstAddr, p.pkt.srcAddr)
	return err
}

func (p *scionPacketProcessor) parsePath() disposition {
	var err error
	p.hopField, err = p.path.GetCurrentHopField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", err)
	}
	p.infoField, err = p.path.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", err)
	}
	// Segments without the Peering flag must consist of at least two HFs:
	// https://github.com/scionproto/scion/issues/4524
	hasSingletonSegment := p.path.PathMeta.SegLen[0] == 1 ||
		p.path.PathMeta.SegLen[1] == 1 ||
		p.path.PathMeta.SegLen[2] == 1
	if !p.infoField.Peer && hasSingletonSegment {
		return errorDiscard("error", malformedPath)
	}
	if !p.path.CurrINFMatchesCurrHF() {
		return errorDiscard("error", malformedPath)
	}
	return pForward
}

func determinePeer(pathMeta scion.MetaHdr, inf path.InfoField) (bool, error) {
	if !inf.Peer {
		return false, nil
	}

	if pathMeta.SegLen[0] == 0 {
		return false, errPeeringEmptySeg0
	}
	if pathMeta.SegLen[1] == 0 {
		return false, errPeeringEmptySeg1

	}
	if pathMeta.SegLen[2] != 0 {
		return false, errPeeringNonemptySeg2
	}

	// The peer hop fields are the last hop field on the first path
	// segment (at SegLen[0] - 1) and the first hop field of the second
	// path segment (at SegLen[0]). The below check applies only
	// because we already know this is a well-formed peering path.
	currHF := pathMeta.CurrHF
	segLen := pathMeta.SegLen[0]
	return currHF == segLen-1 || currHF == segLen, nil
}

func (p *scionPacketProcessor) determinePeer() disposition {
	peer, err := determinePeer(p.path.PathMeta, p.infoField)
	p.peering = peer
	if err != nil {
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) validateHopExpiry() disposition {
	expiration := util.SecsToTime(p.infoField.Timestamp).
		Add(path.ExpTimeToDuration(p.hopField.ExpTime))
	expired := expiration.Before(time.Now())
	if !expired {
		return pForward
	}
	log.Debug("SCMP response", "cause", expiredHop,
		"cons_dir", p.infoField.ConsDir, "if_id", p.pkt.ingress,
		"curr_inf", p.path.PathMeta.CurrINF, "curr_hf", p.path.PathMeta.CurrHF)
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodePathExpired,
		pointer:  p.currentHopPointer(),
	}
	return pSlowPath
}

func (p *scionPacketProcessor) validateIngressID() disposition {
	hdrIngressID := p.hopField.ConsIngress
	errCode := slayers.SCMPCodeUnknownHopFieldIngress
	if !p.infoField.ConsDir {
		hdrIngressID = p.hopField.ConsEgress
		errCode = slayers.SCMPCodeUnknownHopFieldEgress
	}
	if p.pkt.ingress != 0 && p.pkt.ingress != hdrIngressID {
		log.Debug("SCMP response", "cause", ingressInterfaceInvalid,
			"pkt_ingress", hdrIngressID, "router_ingress", p.pkt.ingress)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     errCode,
			pointer:  p.currentHopPointer(),
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) validateSrcDstIA() disposition {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.pkt.ingress == 0 {
		// Outbound
		// Only check SrcIA if first hop, for transit this already checked by ingress router.
		// Note: SCMP error messages triggered by the sibling router may use paths that
		// don't start with the first hop.
		if p.path.IsFirstHop() && !srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if dstIsLocal {
			return p.respInvalidDstIA()
		}
	} else {
		// Inbound
		if srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if p.path.IsLastHop() != dstIsLocal {
			return p.respInvalidDstIA()
		}
	}
	return pForward
}

// invalidSrcIA is a helper to return an SCMP error for an invalid SrcIA.
func (p *scionPacketProcessor) respInvalidSrcIA() disposition {
	log.Debug("SCMP response", "cause", invalidSrcIA)
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodeInvalidSourceAddress,
		pointer:  uint16(slayers.CmnHdrLen + addr.IABytes),
	}
	return pSlowPath
}

// invalidDstIA is a helper to return an SCMP error for an invalid DstIA.
func (p *scionPacketProcessor) respInvalidDstIA() disposition {
	log.Debug("SCMP response", "cause", invalidDstIA)
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodeInvalidDestinationAddress,
		pointer:  uint16(slayers.CmnHdrLen),
	}
	return pSlowPath
}

// validateTransitUnderlaySrc checks that the source address of transit packets
// matches the expected sibling router.
// Provided that underlying network infrastructure prevents address spoofing,
// this check prevents malicious end hosts in the local AS from bypassing the
// SrcIA checks by disguising packets as transit traffic.
func (p *scionPacketProcessor) validateTransitUnderlaySrc() disposition {
	if p.path.IsFirstHop() || p.pkt.ingress != 0 {
		// not a transit packet, nothing to check
		return pForward
	}
	pktIngressID := p.ingressInterface()
	expectedSrc, okE := p.d.internalNextHops[pktIngressID]
	if !okE {
		// Drop
		return errorDiscard("error", invalidSrcAddrForTransit)
	}
	src, okS := netip.AddrFromSlice(p.pkt.srcAddr.IP)
	if !(okS && expectedSrc.Addr() == src) {
		// Drop
		return errorDiscard("error", invalidSrcAddrForTransit)
	}
	return pForward
}

// Validates the egress interface referenced by the current hop.
func (p *scionPacketProcessor) validateEgressID() disposition {
	egressID := p.pkt.egress
	_, ih := p.d.internalNextHops[egressID]
	_, eh := p.d.external[egressID]
	// egress interface must be a known interface
	// packet coming from internal interface, must go to an external interface
	// packet coming from external interface can go to either internal or external interface
	if !ih && !eh || (p.pkt.ingress == 0) && !eh {
		errCode := slayers.SCMPCodeUnknownHopFieldEgress
		if !p.infoField.ConsDir {
			errCode = slayers.SCMPCodeUnknownHopFieldIngress
		}
		log.Debug("SCMP response", "cause", cannotRoute)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     errCode,
			pointer:  p.currentHopPointer(),
		}
		return pSlowPath
	}

	ingressLT, egressLT := p.d.linkTypes[p.pkt.ingress], p.d.linkTypes[egressID]
	if !p.effectiveXover {
		// Check that the interface pair is valid within a single segment.
		// No check required if the packet is received from an internal interface.
		// This case applies to peering hops as a peering hop isn't an effective
		// cross-over (eventhough it is a segment change).
		switch {
		case p.pkt.ingress == 0:
			return pForward
		case ingressLT == topology.Core && egressLT == topology.Core:
			return pForward
		case ingressLT == topology.Child && egressLT == topology.Parent:
			return pForward
		case ingressLT == topology.Parent && egressLT == topology.Child:
			return pForward
		case ingressLT == topology.Child && egressLT == topology.Peer:
			return pForward
		case ingressLT == topology.Peer && egressLT == topology.Child:
			return pForward
		default: // malicious
			log.Debug("SCMP response", "cause", cannotRoute,
				"ingress_id", p.pkt.ingress, "ingress_type", ingressLT,
				"egress_id", egressID, "egress_type", egressLT)
			p.pkt.slowPathRequest = slowPathRequest{
				scmpType: slayers.SCMPTypeParameterProblem,
				code:     slayers.SCMPCodeInvalidPath, // XXX(matzf) new code InvalidHop?,
				pointer:  p.currentHopPointer(),
			}
			return pSlowPath
		}
	}

	// Check that the interface pair is valid on a segment switch.
	// Having a segment change received from the internal interface is never valid.
	// We should never see a peering link traversal either. If that happens
	// treat it as a routing error (not sure if that can happen without an internal
	// error, though).
	switch {
	case ingressLT == topology.Core && egressLT == topology.Child:
		return pForward
	case ingressLT == topology.Child && egressLT == topology.Core:
		return pForward
	case ingressLT == topology.Child && egressLT == topology.Child:
		return pForward
	default:
		log.Debug("SCMP response", "cause", cannotRoute,
			"ingress_id", p.pkt.ingress, "ingress_type", ingressLT,
			"egress_id", egressID, "egress_type", egressLT)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     slayers.SCMPCodeInvalidSegmentChange,
			pointer:  p.currentInfoPointer(),
		}
		return pSlowPath
	}
}

func (p *scionPacketProcessor) updateNonConsDirIngressSegID() disposition {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// For packets destined to peer links this shouldn't be updated.
	if !p.infoField.ConsDir && p.pkt.ingress != 0 && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			return errorDiscard("error", err)
		}
	}
	return pForward
}

func (p *scionPacketProcessor) currentInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*int(p.path.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*p.path.NumINF + path.HopLen*int(p.path.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentMAC() disposition {
	fullMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macInputBuffer[:path.MACBufferSize])
	if subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], fullMac[:path.MacLen]) == 0 {
		log.Debug("SCMP response", "cause", macVerificationFailed,
			"expected", fullMac[:path.MacLen],
			"actual", p.hopField.Mac[:path.MacLen],
			"cons_dir", p.infoField.ConsDir,
			"if_id", p.pkt.ingress, "curr_inf", p.path.PathMeta.CurrINF,
			"curr_hf", p.path.PathMeta.CurrHF, "seg_id", p.infoField.SegID)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     slayers.SCMPCodeInvalidHopFieldMAC,
			pointer:  p.currentHopPointer(),
		}
		return pSlowPath
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC does not need to recalculate it.
	p.cachedMac = fullMac

	return pForward
}

func (p *scionPacketProcessor) resolveInbound() disposition {
	err := p.d.resolveLocalDst(p.pkt.dstAddr, p.scionLayer, p.lastLayer)

	switch err {
	case nil:
		return pForward
	case noSVCBackend:
		log.Debug("SCMP response", "cause", err)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeDestinationUnreachable,
			code:     slayers.SCMPCodeNoRoute,
		}
		return pSlowPath
	case invalidDstAddr, unsupportedV4MappedV6Address, unsupportedUnspecifiedAddress:
		log.Debug("SCMP response", "cause", err)
		p.pkt.slowPathRequest = slowPathRequest{
			scmpType: slayers.SCMPTypeParameterProblem,
			code:     slayers.SCMPCodeInvalidDestinationAddress,
		}
		return pSlowPath
	default:
		return errorDiscard("error", err)
	}
}

func (p *scionPacketProcessor) processEgress() disposition {
	// We are the egress router and if we go in construction direction we
	// need to update the SegID (unless we are effecting a peering hop).
	// When we're at a peering hop, the SegID for this hop and for the next
	// are one and the same, both hops chain to the same parent. So do not
	// update SegID.
	if p.infoField.ConsDir && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return errorDiscard("error", err)
		}
	}
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) doXover() disposition {
	p.effectiveXover = true
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	var err error
	if p.hopField, err = p.path.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	if p.infoField, err = p.path.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) ingressInterface() uint16 {
	info := p.infoField
	hop := p.hopField
	if !p.peering && p.path.IsFirstHopAfterXover() {
		var err error
		info, err = p.path.GetInfoField(int(p.path.PathMeta.CurrINF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
		hop, err = p.path.GetHopField(int(p.path.PathMeta.CurrHF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
	}
	if info.ConsDir {
		return hop.ConsIngress
	}
	return hop.ConsEgress
}

func (p *scionPacketProcessor) egressInterface() uint16 {
	if p.infoField.ConsDir {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

func (p *scionPacketProcessor) validateEgressUp() disposition {
	egressID := p.pkt.egress
	if v, ok := p.d.bfdSessions[egressID]; ok {
		if !v.IsUp() {
			log.Debug("SCMP response", "cause", errBFDSessionDown)
			if _, external := p.d.external[p.pkt.egress]; !external {
				p.pkt.slowPathRequest = slowPathRequest{
					scmpType: slayers.SCMPTypeInternalConnectivityDown,
					code:     0,
				}
			} else {
				p.pkt.slowPathRequest = slowPathRequest{
					scmpType: slayers.SCMPTypeExternalInterfaceDown,
					code:     0,
				}
			}
			return pSlowPath
		}
	}
	return pForward
}

func (p *scionPacketProcessor) handleIngressRouterAlert() disposition {
	if p.pkt.ingress == 0 {
		return pForward
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		typ: slowPathRouterAlertIngress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) ingressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.EgressRouterAlert
	}
	return &p.hopField.IngressRouterAlert
}

func (p *scionPacketProcessor) handleEgressRouterAlert() disposition {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	if _, ok := p.d.external[p.pkt.egress]; !ok {
		return pForward
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		typ: slowPathRouterAlertEgress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) egressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.IngressRouterAlert
	}
	return &p.hopField.EgressRouterAlert
}

func (p *slowPathPacketProcessor) handleSCMPTraceRouteRequest(ifID uint16) error {

	if p.lastLayer.NextLayerType() != slayers.LayerTypeSCMP {
		log.Debug("Packet with router alert, but not SCMP")
		return nil
	}
	scionPld := p.lastLayer.LayerPayload()
	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(scionPld, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMP header of router alert", "err", err)
		return nil
	}
	if scmpH.TypeCode != slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0) {
		log.Debug("Packet with router alert, but not traceroute request",
			"type_code", scmpH.TypeCode)
		return nil
	}
	var scmpP slayers.SCMPTraceroute
	if err := scmpP.DecodeFromBytes(scmpH.Payload, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMPTraceroute", "err", err)
		return nil
	}
	scmpP = slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         p.d.localIA,
		Interface:  uint64(ifID),
	}
	return p.packSCMP(slayers.SCMPTypeTracerouteReply, 0, &scmpP, false)
}

func (p *scionPacketProcessor) validatePktLen() disposition {
	if int(p.scionLayer.PayloadLen) == len(p.scionLayer.Payload) {
		return pForward
	}
	log.Debug("SCMP response", "cause", badPacketSize, "header", p.scionLayer.PayloadLen,
		"actual", len(p.scionLayer.Payload))
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodeInvalidPacketSize,
		pointer:  0,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) validateSrcHost() disposition {
	// We pay for this check only on the first hop.
	if p.scionLayer.SrcIA != p.d.localIA {
		return pForward
	}
	src, err := p.scionLayer.SrcAddr()
	if err == nil && src.IP().Is4In6() {
		err = unsupportedV4MappedV6Address
	}
	if err == nil {
		return pForward
	}

	log.Debug("SCMP response", "cause", err)
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     slayers.SCMPCodeInvalidSourceAddress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) process() disposition {
	if disp := p.parsePath(); disp != pForward {
		return disp
	}
	if disp := p.determinePeer(); disp != pForward {
		return disp
	}
	if disp := p.validateHopExpiry(); disp != pForward {
		return disp
	}
	if disp := p.validateIngressID(); disp != pForward {
		return disp
	}
	if disp := p.validatePktLen(); disp != pForward {
		return disp
	}
	if disp := p.validateTransitUnderlaySrc(); disp != pForward {
		return disp
	}
	if disp := p.validateSrcDstIA(); disp != pForward {
		return disp
	}
	if disp := p.validateSrcHost(); disp != pForward {
		return disp
	}
	if disp := p.updateNonConsDirIngressSegID(); disp != pForward {
		return disp
	}
	if disp := p.verifyCurrentMAC(); disp != pForward {
		return disp
	}
	if disp := p.handleIngressRouterAlert(); disp != pForward {
		return disp
	}
	// Inbound: pkt destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {
		disp := p.resolveInbound()
		if disp != pForward {
			return disp
		}
		p.pkt.trafficType = ttIn
		return pForward
	}

	// Outbound: pkt leaving the local IA. This Could be:
	// * Pure outbound: from this AS, in via internal, out via external.
	// * ASTransit in: from another AS, in via external, out via internal to other BR.
	// * ASTransit out: from another AS, in via internal from other BR, out via external.
	// * BRTransit: from another AS, in via external, out via external.
	if p.path.IsXover() && !p.peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if disp := p.doXover(); disp != pForward {
			return disp
		}
		// doXover() has changed the current segment and hop field.
		// We need to validate the new hop field.
		if disp := p.validateHopExpiry(); disp != pForward {
			return disp
		}
		// verify the new block
		if disp := p.verifyCurrentMAC(); disp != pForward {
			return disp
		}
	}

	// Assign egress interface to the packet early. ICMP responses, if we make any, will need this.
	// Even if the egress interface is not valid, it can be useful in SCMP reporting.
	egressID := p.egressInterface()
	p.pkt.egress = egressID

	if disp := p.validateEgressID(); disp != pForward {
		return disp
	}

	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if disp := p.handleEgressRouterAlert(); disp != pForward {
		return disp
	}
	if disp := p.validateEgressUp(); disp != pForward {
		return disp
	}

	if _, ok := p.d.external[egressID]; ok {
		// Not ASTransit in
		if disp := p.processEgress(); disp != pForward {
			return disp
		}
		// Finish deciding the trafficType...
		var tt trafficType
		if p.scionLayer.SrcIA == p.d.localIA {
			// Pure outbound
			tt = ttOut
		} else if p.pkt.ingress == 0 {
			// ASTransit out
			tt = ttOutTransit
		} else {
			// Therefore it is BRTransit
			tt = ttBrTransit
		}
		p.pkt.trafficType = tt
		return pForward
	}

	// ASTransit in: pkt leaving this AS through another BR.
	if a, ok := p.d.internalNextHops[egressID]; ok {
		p.pkt.trafficType = ttInTransit
		updateNetAddrFromAddrPort(p.pkt.dstAddr, a)
		// The packet must go to the other router via the internal interface.
		p.pkt.egress = 0
		return pForward
	}

	errCode := slayers.SCMPCodeUnknownHopFieldEgress
	if !p.infoField.ConsDir {
		errCode = slayers.SCMPCodeUnknownHopFieldIngress
	}
	log.Debug("SCMP response", "cause", cannotRoute)
	p.pkt.slowPathRequest = slowPathRequest{
		scmpType: slayers.SCMPTypeParameterProblem,
		code:     errCode,
		pointer:  p.currentHopPointer(),
	}
	return pSlowPath
}

func (p *scionPacketProcessor) processOHP() disposition {
	s := p.scionLayer
	ohp, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return errorDiscard("error", malformedPath)
	}
	if !ohp.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return errorDiscard("error", malformedPath)
	}

	// OHP leaving our IA
	if p.pkt.ingress == 0 {
		if !p.d.localIA.Equal(s.SrcIA) {
			// TODO parameter problem -> invalid path
			return errorDiscard("error", cannotRoute)
		}
		neighborIA, ok := p.d.neighborIAs[ohp.FirstHop.ConsEgress]
		if !ok {
			// TODO parameter problem invalid interface
			return errorDiscard("error", cannotRoute)
		}
		if !neighborIA.Equal(s.DstIA) {
			return errorDiscard("error", cannotRoute)
		}
		mac := path.MAC(p.mac, ohp.Info, ohp.FirstHop, p.macInputBuffer[:path.MACBufferSize])
		if subtle.ConstantTimeCompare(ohp.FirstHop.Mac[:], mac[:]) == 0 {
			// TODO parameter problem -> invalid MAC
			return errorDiscard("error", macVerificationFailed)
		}
		ohp.Info.UpdateSegID(ohp.FirstHop.Mac)

		if err := updateSCIONLayer(p.pkt.rawPacket, s, p.buffer); err != nil {
			return errorDiscard("error", err)
		}
		p.pkt.egress = ohp.FirstHop.ConsEgress
		return pForward
	}

	// OHP entering our IA
	if !p.d.localIA.Equal(s.DstIA) {
		return errorDiscard("error", cannotRoute)
	}
	neighborIA := p.d.neighborIAs[p.pkt.ingress]
	if !neighborIA.Equal(s.SrcIA) {
		return errorDiscard("error", cannotRoute)
	}

	ohp.SecondHop = path.HopField{
		ConsIngress: p.pkt.ingress,
		ExpTime:     ohp.FirstHop.ExpTime,
	}
	// XXX(roosd): Here we leak the buffer into the SCION packet header.
	// This is okay because we do not operate on the buffer or the packet
	// for the rest of processing.
	ohp.SecondHop.Mac = path.MAC(p.mac, ohp.Info, ohp.SecondHop,
		p.macInputBuffer[:path.MACBufferSize])

	if err := updateSCIONLayer(p.pkt.rawPacket, s, p.buffer); err != nil {
		return errorDiscard("error", err)
	}
	err := p.d.resolveLocalDst(p.pkt.dstAddr, s, p.lastLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	return pForward
}

func (d *DataPlane) resolveLocalDst(
	resolvedDst *net.UDPAddr,
	s slayers.SCION,
	lastLayer gopacket.DecodingLayer,
) error {

	dst, err := s.DstAddr()
	if err != nil {
		return invalidDstAddr
	}
	switch dst.Type() {
	case addr.HostTypeSVC:
		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		a, ok := d.svc.Any(dst.SVC().Base())
		if !ok {
			return noSVCBackend
		}
		// if SVC address is outside the configured port range we send to the fix
		// port.
		if a.Port() < d.dispatchedPortStart || a.Port() > d.dispatchedPortEnd {
			updateNetAddrFromAddrAndPort(resolvedDst, a.Addr(), topology.EndhostPort)
		} else {
			updateNetAddrFromAddrPort(resolvedDst, a)
		}
		return nil
	case addr.HostTypeIP:
		// Parse UPD port and rewrite underlay IP/UDP port
		// TODO(jiceatscion): IP() is returned by value. The cost of copies adds up.
		dstIP := dst.IP()
		if dstIP.Is4In6() {
			return unsupportedV4MappedV6Address
		}
		// Zero IP addresses (per IsUnspecified()) are not supported. Zero valued netip.Addr objects
		// (per IsInvalid()) cannot happen here as dstIP is initialized from packet header data.
		if dstIP.IsUnspecified() {
			return unsupportedUnspecifiedAddress
		}
		return d.addEndhostPort(resolvedDst, lastLayer, dstIP)
	default:
		panic("unexpected address type returned from DstAddr")
	}
}

func (d *DataPlane) addEndhostPort(
	resolvedDst *net.UDPAddr,
	lastLayer gopacket.DecodingLayer,
	dst netip.Addr,
) error {

	// Parse UPD port and rewrite underlay IP/UDP port
	l4Type := nextHdr(lastLayer)
	port := uint16(topology.EndhostPort)

	switch l4Type {
	case slayers.L4UDP:
		if len(lastLayer.LayerPayload()) < 8 {
			// TODO(JordiSubira): Treat this as a parameter problem
			return serrors.New("SCION/UDP header len too small", "length",
				len(lastLayer.LayerPayload()))
		}
		port = binary.BigEndian.Uint16(lastLayer.LayerPayload()[2:])
		if port < d.dispatchedPortStart || port > d.dispatchedPortEnd {
			port = topology.EndhostPort
		}
	case slayers.L4SCMP:
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return serrors.WrapStr("decoding SCMP layer for extracting endhost dst port", err)
		}
		port, err = getDstPortSCMP(&scmpLayer)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return serrors.WrapStr("getting dst port from SCMP message", err)
		}
		// if the SCMP dst port is outside the range, we send it to the EndhostPort
		if port < d.dispatchedPortStart || port > d.dispatchedPortEnd {
			port = topology.EndhostPort
		}
	default:
		log.Debug("msg", "protocol", l4Type)
	}
	updateNetAddrFromAddrAndPort(resolvedDst, dst, port)
	return nil
}

func getDstPortSCMP(scmp *slayers.SCMP) (uint16, error) {
	// XXX(JordiSubira): This implementation is far too slow for the dataplane.
	// We should reimplement this with fewer helpers and memory allocations, since
	// our sole goal is to parse the L4 port or identifier in the offending packets.
	if scmp.TypeCode.Type() == slayers.SCMPTypeEchoRequest ||
		scmp.TypeCode.Type() == slayers.SCMPTypeTracerouteRequest {
		return topology.EndhostPort, nil
	}
	if scmp.TypeCode.Type() == slayers.SCMPTypeEchoReply {
		var scmpEcho slayers.SCMPEcho
		err := scmpEcho.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return 0, err
		}
		return scmpEcho.Identifier, nil
	}
	if scmp.TypeCode.Type() == slayers.SCMPTypeTracerouteReply {
		var scmpTraceroute slayers.SCMPTraceroute
		err := scmpTraceroute.DecodeFromBytes(scmp.Payload, gopacket.NilDecodeFeedback)
		if err != nil {
			return 0, err
		}
		return scmpTraceroute.Identifier, nil
	}

	// Drop unknown SCMP error messages.
	if scmp.NextLayerType() == gopacket.LayerTypePayload {
		return 0, serrors.New("unsupported SCMP error message",
			"type", scmp.TypeCode.Type())
	}
	l, err := decodeSCMP(scmp)
	if err != nil {
		return 0, err
	}
	if len(l) != 2 {
		return 0, serrors.New("SCMP error message without payload")
	}
	gpkt := gopacket.NewPacket(*l[1].(*gopacket.Payload), slayers.LayerTypeSCION,
		gopacket.DecodeOptions{
			NoCopy: true,
		},
	)

	// If the offending packet was UDP/SCION, use the source port to deliver.
	if udp := gpkt.Layer(slayers.LayerTypeSCIONUDP); udp != nil {
		port := udp.(*slayers.UDP).SrcPort
		// XXX(roosd): We assume that the zero value means the UDP header is
		// truncated. This flags packets of misbehaving senders as truncated, if
		// they set the source port to 0. But there is no harm, since those
		// packets are destined to be dropped anyway.
		if port == 0 {
			return 0, serrors.New("SCMP error with truncated UDP header")
		}
		return port, nil
	}

	// If the offending packet was SCMP/SCION, and it is an echo or traceroute,
	// use the Identifier to deliver. In all other cases, the message is dropped.
	if scmp := gpkt.Layer(slayers.LayerTypeSCMP); scmp != nil {

		tc := scmp.(*slayers.SCMP).TypeCode
		// SCMP Error messages in response to an SCMP error message are not allowed.
		if !tc.InfoMsg() {
			return 0, serrors.New("SCMP error message in response to SCMP error message",
				"type", tc.Type())
		}
		// We only support echo and traceroute requests.
		t := tc.Type()
		if t != slayers.SCMPTypeEchoRequest && t != slayers.SCMPTypeTracerouteRequest {
			return 0, serrors.New("unsupported SCMP info message", "type", t)
		}

		var port uint16
		// Extract the port from the echo or traceroute ID field.
		if echo := gpkt.Layer(slayers.LayerTypeSCMPEcho); echo != nil {
			port = echo.(*slayers.SCMPEcho).Identifier
		} else if tr := gpkt.Layer(slayers.LayerTypeSCMPTraceroute); tr != nil {
			port = tr.(*slayers.SCMPTraceroute).Identifier
		} else {
			return 0, serrors.New("SCMP error with truncated payload")
		}
		return port, nil
	}
	return 0, serrors.New("unknown SCION SCMP content")
}

// decodeSCMP decodes the SCMP payload. WARNING: Decoding is done with NoCopy set.
func decodeSCMP(scmp *slayers.SCMP) ([]gopacket.SerializableLayer, error) {
	gpkt := gopacket.NewPacket(scmp.Payload, scmp.NextLayerType(),
		gopacket.DecodeOptions{NoCopy: true})
	layers := gpkt.Layers()
	if len(layers) == 0 || len(layers) > 2 {
		return nil, serrors.New("invalid number of SCMP layers", "count", len(layers))
	}
	ret := make([]gopacket.SerializableLayer, len(layers))
	for i, l := range layers {
		s, ok := l.(gopacket.SerializableLayer)
		if !ok {
			return nil, serrors.New("invalid SCMP layer, not serializable", "index", i)
		}
		ret[i] = s
	}
	return ret, nil
}

// TODO(matzf) this function is now only used to update the OneHop-path.
// This should be changed so that the OneHop-path can be updated in-place, like
// the scion.Raw path.
func updateSCIONLayer(rawPkt []byte, s slayers.SCION, buffer gopacket.SerializeBuffer) error {
	if err := buffer.Clear(); err != nil {
		return err
	}
	if err := s.SerializeTo(buffer, gopacket.SerializeOptions{}); err != nil {
		return err
	}
	// TODO(lukedirtwalker): We should add a method to the scion layers
	// which can write into the existing buffer, see also the discussion in
	// https://fsnets.slack.com/archives/C8ADBBG0J/p1592805884250700
	rawContents := buffer.Bytes()
	copy(rawPkt[:len(rawContents)], rawContents)
	return nil
}

type bfdSend struct {
	conn             BatchConn
	srcAddr, dstAddr netip.AddrPort
	scn              *slayers.SCION
	ohp              *onehop.Path
	mac              hash.Hash
	macBuffer        []byte
	buffer           gopacket.SerializeBuffer
}

// newBFDSend creates and initializes a BFD Sender
func newBFDSend(conn BatchConn, srcIA, dstIA addr.IA, srcAddr, dstAddr netip.AddrPort,
	ifID uint16, mac hash.Hash) (*bfdSend, error) {

	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4BFD,
		SrcIA:        srcIA,
		DstIA:        dstIA,
	}

	if !srcAddr.IsValid() {
		return nil, serrors.New("invalid source IP", "ip", srcAddr)
	}
	if !dstAddr.IsValid() {
		return nil, serrors.New("invalid source IP", "ip", srcAddr)
	}

	srcAddrIP := srcAddr.Addr()
	dstAddrIP := dstAddr.Addr()
	if err := scn.SetSrcAddr(addr.HostIP(srcAddrIP)); err != nil {
		panic(err) // Must work
	}
	if err := scn.SetDstAddr(addr.HostIP(dstAddrIP)); err != nil {
		panic(err) // Must work
	}

	var ohp *onehop.Path
	if ifID == 0 {
		scn.PathType = empty.PathType
		scn.Path = &empty.Path{}
	} else {
		ohp = &onehop.Path{
			Info: path.InfoField{
				ConsDir: true,
				// Timestamp set in Send
			},
			FirstHop: path.HopField{
				ConsEgress: ifID,
				ExpTime:    hopFieldDefaultExpTime,
			},
		}
		scn.PathType = onehop.PathType
		scn.Path = ohp
	}

	return &bfdSend{
		conn:      conn,
		srcAddr:   srcAddr,
		dstAddr:   dstAddr,
		scn:       scn,
		ohp:       ohp,
		mac:       mac,
		macBuffer: make([]byte, path.MACBufferSize),
		buffer:    gopacket.NewSerializeBuffer(),
	}, nil
}

func (b *bfdSend) String() string {
	return b.srcAddr.String()
}

// Send sends out a BFD message.
// Due to the internal state of the MAC computation, this is not goroutine
// safe.
func (b *bfdSend) Send(bfd *layers.BFD) error {
	if b.ohp != nil {
		// Subtract 10 seconds to deal with possible clock drift.
		ohp := b.ohp
		ohp.Info.Timestamp = uint32(time.Now().Unix() - 10)
		ohp.FirstHop.Mac = path.MAC(b.mac, ohp.Info, ohp.FirstHop, b.macBuffer)
	}

	err := gopacket.SerializeLayers(b.buffer, gopacket.SerializeOptions{FixLengths: true},
		b.scn, bfd)
	if err != nil {
		return err
	}
	_, err = b.conn.WriteTo(b.buffer.Bytes(), b.dstAddr)
	return err
}

func (p *slowPathPacketProcessor) prepareSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	isError bool,
) ([]byte, error) {

	// *copy* and reverse path -- the original path should not be modified as this writes directly
	// back to rawPkt (quote).
	var path *scion.Raw
	pathType := p.scionLayer.Path.Type()
	switch pathType {
	case scion.PathType:
		var ok bool
		path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
				"path type", pathType)
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
				"path type", pathType)
		}
		path = epicPath.ScionPath
	default:
		return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
			"path type", pathType)
	}
	decPath, err := path.ToDecoded()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "decoding raw path")
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := revPathTmp.(*scion.Decoded)

	peering, err := determinePeer(revPath.PathMeta, revPath.InfoFields[revPath.PathMeta.CurrINF])
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "peering cannot be determined")
	}

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() && !peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	_, external := p.d.external[p.pkt.ingress]
	if external {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir && !peering {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "incrementing path for SCMP")
		}
	}

	// create new SCION header for reply.
	var scionL slayers.SCION
	scionL.FlowID = p.scionLayer.FlowID
	scionL.TrafficClass = p.scionLayer.TrafficClass
	scionL.PathType = revPath.Type()
	scionL.Path = revPath
	scionL.DstIA = p.scionLayer.SrcIA
	scionL.SrcIA = p.d.localIA
	scionL.DstAddrType = p.scionLayer.SrcAddrType
	scionL.RawDstAddr = p.scionLayer.RawSrcAddr
	scionL.NextHdr = slayers.L4SCMP

	if err := scionL.SetSrcAddr(addr.HostIP(p.d.internalIP)); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting src addr")
	}
	typeCode := slayers.CreateSCMPTypeCode(typ, code)
	scmpH := slayers.SCMP{TypeCode: typeCode}
	scmpH.SetNetworkLayerForChecksum(&scionL)

	needsAuth := false
	if p.d.ExperimentalSCMPAuthentication {
		// Error messages must be authenticated.
		// Traceroute are OPTIONALLY authenticated ONLY IF the request
		// was authenticated.
		// TODO(JordiSubira): Reuse the key computed in p.hasValidAuth
		// if SCMPTypeTracerouteReply to create the response.
		needsAuth = isError ||
			(scmpH.TypeCode.Type() == slayers.SCMPTypeTracerouteReply &&
				p.hasValidAuth(time.Now()))
	}

	var quote []byte
	if isError {
		// add quote for errors.
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len()
		if needsAuth {
			hdrLen += e2eAuthHdrLen
		}
		switch scmpH.TypeCode.Type() {
		case slayers.SCMPTypeExternalInterfaceDown:
			hdrLen += 20
		case slayers.SCMPTypeInternalConnectivityDown:
			hdrLen += 28
		default:
			hdrLen += 8
		}
		quote = p.pkt.rawPacket
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if len(quote) > maxQuoteLen {
			quote = quote[:maxQuoteLen]
		}
	}

	if err := p.buffer.Clear(); err != nil {
		return nil, err
	}
	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// First write the SCMP message only without the SCION header(s) to get a buffer that we
	// can (re-)use as input in the MAC computation.
	// XXX(matzf) could we use iovec gather to avoid copying quote?
	err = gopacket.SerializeLayers(p.buffer, sopts, &scmpH, scmpP, gopacket.Payload(quote))
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCMP message")
	}

	if needsAuth {
		var e2e slayers.EndToEndExtn
		scionL.NextHdr = slayers.End2EndClass

		now := time.Now()
		dstA, err := scionL.DstAddr()
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "parsing destination address")
		}
		key, err := p.drkeyProvider.GetASHostKey(now, scionL.DstIA, dstA)
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "retrieving DRKey")
		}
		if err := p.resetSPAOMetadata(key, now); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "resetting SPAO header")
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key.Key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        p.buffer.Bytes(),
			},
			p.macInputBuffer,
			p.optAuth.Authenticator(),
		)
		if err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "computing CMAC")
		}
		if err := e2e.SerializeTo(p.buffer, sopts); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCION E2E headers")
		}
	} else {
		scionL.NextHdr = slayers.L4SCMP
	}
	if err := scionL.SerializeTo(p.buffer, sopts); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCION header")
	}

	log.Debug("scmp", "typecode", scmpH.TypeCode)
	return p.buffer.Bytes(), nil
}

func (p *slowPathPacketProcessor) resetSPAOMetadata(key drkey.ASHostKey, now time.Time) error {
	// For creating SCMP responses we use sender side.
	dir := slayers.PacketAuthSenderSide
	drkeyType := slayers.PacketAuthASHost

	spi, err := slayers.MakePacketAuthSPIDRKey(uint16(drkey.SCMP), drkeyType, dir)
	if err != nil {
		return err
	}

	timestamp, err := spao.RelativeTimestamp(key.Epoch, now)
	if err != nil {
		return err
	}

	return p.optAuth.Reset(slayers.PacketAuthOptionParams{
		SPI:         spi,
		Algorithm:   slayers.PacketAuthCMAC,
		TimestampSN: timestamp,
		Auth:        zeroBuffer,
	})
}

func (p *slowPathPacketProcessor) hasValidAuth(t time.Time) bool {
	// Check if e2eLayer was parsed for this packet
	if !p.lastLayer.CanDecode().Contains(slayers.LayerTypeEndToEndExtn) {
		return false
	}
	// Parse incoming authField
	e2eLayer := &slayers.EndToEndExtn{}
	if err := e2eLayer.DecodeFromBytes(
		p.e2eLayer.Contents,
		gopacket.NilDecodeFeedback,
	); err != nil {
		return false
	}
	e2eOption, err := e2eLayer.FindOption(slayers.OptTypeAuthenticator)
	if err != nil {
		return false
	}
	authOption, err := slayers.ParsePacketAuthOption(e2eOption)
	if err != nil {
		return false
	}
	// Computing authField
	// the sender should have used the receiver side key, i.e., K_{localIA-remoteIA:remoteHost}
	// where remoteIA == p.scionLayer.SrcIA and remoteHost == srcAddr
	// (for the incoming packet).
	srcAddr, err := p.scionLayer.SrcAddr()
	if err != nil {
		return false
	}
	key, err := p.drkeyProvider.GetKeyWithinAcceptanceWindow(
		t,
		authOption.TimestampSN(),
		p.scionLayer.SrcIA,
		srcAddr,
	)
	if err != nil {
		log.Debug("Selecting key to authenticate the incoming packet", "err", err)
		return false
	}

	_, err = spao.ComputeAuthCMAC(
		spao.MACInput{
			Key:        key.Key[:],
			Header:     authOption,
			ScionLayer: &p.scionLayer,
			PldType:    slayers.L4SCMP,
			Pld:        p.lastLayer.LayerPayload(),
		},
		p.macInputBuffer,
		p.validAuthBuf,
	)
	if err != nil {
		return false
	}
	// compare incoming authField with computed authentication tag
	return subtle.ConstantTimeCompare(authOption.Authenticator(), p.validAuthBuf) != 0
}

// decodeLayers implements roughly the functionality of
// gopacket.DecodingLayerParser, but customized to our use case with a "base"
// layer and additional, optional layers in the given order.
// Returns the last decoded layer.
func decodeLayers(data []byte, base gopacket.DecodingLayer,
	opts ...gopacket.DecodingLayer) (gopacket.DecodingLayer, error) {

	if err := base.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	last := base
	for _, opt := range opts {
		if opt.CanDecode().Contains(last.NextLayerType()) {
			data := last.LayerPayload()
			if err := opt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				return nil, err
			}
			last = opt
		}
	}
	return last, nil
}

func nextHdr(layer gopacket.DecodingLayer) slayers.L4ProtocolType {
	switch v := layer.(type) {
	case *slayers.SCION:
		return v.NextHdr
	case *slayers.EndToEndExtnSkipper:
		return v.NextHdr
	case *slayers.HopByHopExtnSkipper:
		return v.NextHdr
	default:
		return slayers.L4None
	}
}

// initMetrics initializes the metrics related to packet forwarding. The counters are already
// instantiated for all the relevant interfaces so this will not have to be repeated during packet
// forwarding.
func (d *DataPlane) initMetrics() {
	d.forwardingMetrics = make(map[uint16]interfaceMetrics)
	d.forwardingMetrics[0] = newInterfaceMetrics(d.Metrics, 0, d.localIA, d.neighborIAs)
	for ifID := range d.external {
		if _, notOwned := d.internalNextHops[ifID]; notOwned {
			continue
		}
		d.forwardingMetrics[ifID] = newInterfaceMetrics(d.Metrics, ifID, d.localIA, d.neighborIAs)
	}

	// Start our custom /proc/pid/stat collector to export iowait time and (in the future) other
	// process-wide metrics that prometheus does not.
	err := processmetrics.Init()

	// we can live without these metrics. Just log the error.
	if err != nil {
		log.Error("Could not initialize processmetrics", "err", err)
	}
}

// updateNetAddrFromAddrPort() updates a net.UDPAddr address to be the same as the
// given netip.AddrPort. newDst.Addr() returns the IP by value. The compiler may or
// may not inline the call and optimize out the copy. It is doubtful that manually inlining
// increases the chances that the copy get elided. TODO(jiceatscion): experiment.
func updateNetAddrFromAddrPort(netAddr *net.UDPAddr, newDst netip.AddrPort) {
	updateNetAddrFromAddrAndPort(netAddr, newDst.Addr(), newDst.Port())
}

// updateNetAddrFromAddrAndPort() updates a net.UDPAddr address to be the same IP and port as
// the given netip.Addr and unigned port.
//
// We handle dstAddr so we don't make the GC work. The issue is the IP address slice
// that's in dstAddr. The packet, along with its address and IP slice, gets copied from a channel
// into a local variable. Then after we modify it, all gets copied to the some other channel and
// eventually it gets copied back to the pool. If we replace the destAddr.IP at any point,
// the old backing array behind the destAddr.IP slice ends-up on the garbage pile. To prevent that,
// we update the IP address in-place (we make the length 0 to represent the 0 address).
func updateNetAddrFromAddrAndPort(netAddr *net.UDPAddr, addr netip.Addr, port uint16) {
	netAddr.Port = int(port)
	netAddr.Zone = addr.Zone()
	if addr.Is4() {
		outIpBytes := addr.As4()     // Must store explicitly in order to copy
		netAddr.IP = netAddr.IP[0:4] // Update slice
		copy(netAddr.IP, outIpBytes[:])
	} else if addr.Is6() {
		outIpBytes := addr.As16()
		netAddr.IP = netAddr.IP[0:16]
		copy(netAddr.IP, outIpBytes[:])
	} else {
		// That's a zero address. We translate in to something resembling a nil IP.
		// Nothing gets discarded as we keep the slice (and its reference to the backing array).
		// To that end, we cannot make it nil. We have to make its length zero.
		netAddr.IP = netAddr.IP[0:0]
	}
}

// updateNetAddrFromNetAddr() copies fromNetAddr into netAddr while re-using the IP slice
// embedded in netAddr. This is to avoid giving work to the GC. Nil IPs get
// converted into empty slices. The backing array isn't discarded.
func updateNetAddrFromNetAddr(netAddr *net.UDPAddr, fromNetAddr *net.UDPAddr) {
	netAddr.Port = fromNetAddr.Port
	netAddr.Zone = fromNetAddr.Zone
	netAddr.IP = netAddr.IP[0:len(fromNetAddr.IP)]
	copy(netAddr.IP, fromNetAddr.IP)
}
