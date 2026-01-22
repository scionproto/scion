// Copyright 2020 Anapaya Systems
// Copyright 2023 ETH Zurich
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

package router

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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
	pr "github.com/scionproto/scion/router/priority"
)

const (
	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	// TODO(multi_underlay): The buffer size should be a function of the collection of
	// underlays (the largest frame size of all the enabled ones).
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

	// For SCMP packet quoting. A strict minimum of 28 is required. Much more is recommended.
	minHeadroom      = 512
	_           uint = minHeadroom - slayers.MaxSCMPHeaderSize // assert >= 28
)

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages) (int, error)
	WriteBatch(msgs underlayconn.Messages, flags int) (int, error)
	Close() error
}

// underlayProviders is a map of our underlay providers. Each entry associates a name with a
// NewProviderFn. A new instance of that provider is created by every invocation so multiple
// dataplane instances can co-exist (as is routinely done by tests).
var underlayProviders map[string]NewProviderFn

// AddUnderlay registers the named factory function.
func AddUnderlay(name string, newProvider func(int, int, int) UnderlayProvider) {
	if underlayProviders == nil {
		underlayProviders = make(map[string]NewProviderFn)
	}
	underlayProviders[name] = newProvider
}

type disposition int

const (
	pDiscard disposition = iota // Zero value, default.
	pForward
	pSlowPath
	pDone
)

// Packet aggregates buffers and ancillary metadata related to one packet.
// That is everything we need to pass-around while processing a packet. The motivation is to save on
// copy (pass everything via one reference) AND garbage collection (reuse everything).
// The buffer is allocated in a separate location (but still reused) to keep the packet structures
// tightly packed (might not matter, though).
// Golang gives precious little guarantees about alignment and padding. We do it ourselves in such
// a way that Go has no sane reason to add any padding. Everything is 8 byte aligned (on 64 bit
// arch) until SlowpathRequest which is 4 bytes long. The rest is in decreasing order of size and
// size-aligned. We want to fit neatly into cache lines, so we need to fit in 64 bytes. The padding
// required to occupy exactly 64 bytes depends on the architecture.
//
// Note(juagargi): if the Packet struct grows larger than 64 bytes, it should have a size multiple
// of 64 bytes. This prevents "false sharing", i.e. having the same bytes being accessed by
// multiple threads simultaneously, thus failing cache coherence and hurting performance.
// This "Packet struct alignment to 64 bytes" is achieved through the presence of the field
// `_ [_pad]byte`. The value `_pad` is computed via a helper struct `alignHelperForPacket`,
// who contains the same exact fields and in the same order as in Packet.
// The presence of the _ [_pad]field needs to be not at the last position of the struct for there
// is a specific case (with _pad==0) where the compiler would add extra padding to avoid pointer
// aliasing with the next Packet object. The last field in the structure (QueueIndex PriorityLabel)
// must not introduce additional padding due to its alignment.
type Packet struct {
	// The useful part of the raw packet at a point in time (i.e. a slice of the full buffer).  It
	// can be any portion of the full buffer; not necessarily the start. This code maintains the
	// invariant that RawPacket always represents the portion of a packet that immediately follows
	// any underlay provider header. See also dataplane.underlayHeadroom.
	RawPacket []byte
	// The entire packet buffer. We don't need it as a slice; we know its size.
	buffer *[bufSize]byte
	// The source address during ingest and the destination during forwarding. We never need both
	// src and dst at the same time. The real type is only known to underlay provider that sets it.
	RemoteAddr unsafe.Pointer
	// The ingest link; which can give us the ifID, scope, bfdSession...
	Link Link
	// Additional metadata in case the packet is put on the slow path. Updated in-place.
	slowPathRequest slowPathRequest
	// The egress on which this packet must leave. This is set by the processing routine.
	egress uint16
	// The type of traffic. This is used for metrics at the forwarding stage, but is most
	// economically determined at the processing stage. So store it here. It's 2 bytes long.
	trafficType trafficType
	// The struct padding field cannot be the last field of the struct. This is because if the
	// helper constant _pad is zero and the field is at the end, the compiler will need to avoid
	// aliasing this field with the next struct's pointer (e.g. in an array).
	// Since the real last field of this struct is a byte long, this does't introduce alignment
	// issues (and thus does not modify the final size of the struct regardless of the value
	// of _pad). See notes for the Packet struct.
	_ [_pad]byte
	// Priority forwarding label: packets with more priority are forwarded first
	PriorityLabel pr.PriorityLabel
}

// alignHelperForPacket is only used to compute the initial size of the Packet struct without
// any extra padding. Since we can't define Packet recursively in terms of Packet without padding,
// an extra struct is necessary.
// The alignHelperForPacket fields must be kept in synchrony with Packet.
type alignHelperForPacket struct {
	RawPacket       []byte
	buffer          *[bufSize]byte
	RemoteAddr      unsafe.Pointer
	Link            Link
	slowPathRequest slowPathRequest
	egress          uint16
	trafficType     trafficType
	QueueIndex      pr.PriorityLabel
}

// Make sure that the packet structure has the size we expect.
const (
	_pad = (64 - int(unsafe.Sizeof(alignHelperForPacket{})%64)) % 64
)

// Fail (negative array size) if the struct is not a multiple of 64.
var _ [-(int(unsafe.Sizeof(Packet{}) % 64))]byte

// Keep this 4 bytes long. See comment for packet.
type slowPathRequest struct {
	pointer uint16
	spType  slowPathType
	code    slayers.SCMPCode
}

// initPacket configures the given blank packet (and returns it, for convenience).
func (p *Packet) init(buffer *[bufSize]byte) *Packet {
	p.buffer = buffer
	p.RawPacket = p.buffer[:]
	return p
}

// reset() makes the packet ready to receive a new underlay message. We adjust the RawPacket slice
// relative to the buffer, so there's enough headroom for any underlay headers.
func (p *Packet) reset(headroom int) {
	*p = Packet{
		buffer:        p.buffer,            // keep the buffer
		RawPacket:     p.buffer[headroom:], // restore the full packet capacity (minus headroom).
		PriorityLabel: pr.WithBestEffort,   // Default to best-effort.
	}
	// Everything else is reset to zero value.
}

// WithHeader returns the a slice of the underlying packet buffer that represents the same bytes as
// p.rawPacket[:] plus the n prededing bytes. This slice is meant to be used when receiving a raw
// packet with an n bytes header, such that the payload is exactly at p.rawPacket[0:]. p.RawPacket
// is *not* modified. This method panics if n is greater than the available headroom in the packet
// buffer.
func (p *Packet) WithHeader(n int) []byte {
	headroom := len(p.buffer) - cap(p.RawPacket) - n

	// A negative value is a panicable offense.
	return p.buffer[headroom:]
}

// PacketPool allocates and resets packets. There is one packet pool per instance of the dataplane,
// shared between all its underlay instances. This structure can be shared by copying (and doing so
// is more efficient) because headroom is never changed after construction and channel is a
// reference type.
type PacketPool struct {
	pool     chan *Packet
	headroom int
}

// Get fetches a packet from the pool and returns it initialized with the proper headroom. That is,
// pkt.rawPacket[0:] is where the packet's payload must go. Underlay providers may use any part of
// that, and MUST update the pkt.rawPacket slice to indicate where the packet's payload starts.
// However they may only use the preceding portion of the packet buffer to store a link-layer
// header. See also WithHeader
func (p *PacketPool) Get() *Packet {
	pkt := <-p.pool
	pkt.reset(p.headroom)
	return pkt
}

// Put returns the given packet to the pool.
func (p *PacketPool) Put(pkt *Packet) {
	p.pool <- pkt

}

// makePacketPool creates a packetpool of size poolSize, that configures packet buffers with the
// given headroom. The pool is initially empty. Packets must be added separately.
func makePacketPool(poolSize, headroom int) PacketPool {
	return PacketPool{pool: make(chan *Packet, poolSize), headroom: headroom}
}

// DataPlane contains a SCION Border Router's forwarding logic. It reads packets
// from multiple sockets, performs routing, and sends them to their destinations
// (after updating the path, if that is needed).
type dataPlane struct {
	underlays           map[string]UnderlayProvider
	interfaces          [math.MaxUint16 + 1]Link
	numInterfaces       int
	linkTypes           [math.MaxUint16 + 1]topology.LinkType
	neighborIAs         [math.MaxUint16 + 1]addr.IA
	localHost           addr.Host
	macFactory          func() hash.Hash
	localIA             addr.IA
	mtx                 sync.Mutex
	running             atomic.Bool
	Metrics             *Metrics
	dispatchedPortStart uint16
	dispatchedPortEnd   uint16

	ExperimentalSCMPAuthentication bool
	RunConfig                      RunConfig

	// The pool that stores all the packet buffers as described in the design document. See
	// https://github.com/scionproto/scion/blob/master/doc/dev/design/BorderRouter.rst
	// To avoid garbage collection, most the meta-data that is produced during the processing of a
	// packet is kept in a data structure (packet struct) that is pooled and recycled along with
	// corresponding packet buffer. The packet struct refers permanently to the packet buffer. The
	// packet structure is fetched from the pool passed-around through the various channels and
	// returned to the pool. To reduce the cost of copying, the packet structure is passed by
	// reference.
	packetPool PacketPool

	// underlayHeadRoom is the minimum headroom that must be reserved at the front of every packet
	// to ensure that every underlay provider can prepend its underlay header without copying. It
	// is established by collecting the headroom requirement of every underlay provider. Underlay
	// providers deliver incoming packets such that the RawPacket slice starts exactly after the
	// link layer header. Underlay providers may use the preceding part of the packet buffer to
	// receive the link layer header.
	underlayHeadroom int
}

var (
	ErrUnsupportedV4MappedV6Address  = errors.New("unsupported v4mapped IP v6 address")
	ErrUnsupportedUnspecifiedAddress = errors.New("unsupported unspecified address")
	ErrNoSVCBackend                  = errors.New("cannot find internal IP for the SVC")

	errAlreadySet                    = errors.New("already set")
	errInvalidSrcIA                  = errors.New("invalid source ISD-AS")
	errInvalidDstIA                  = errors.New("invalid destination ISD-AS")
	errInvalidSrcAddrForTransit      = errors.New("invalid source address for transit pkt")
	errInvalidDstAddr                = errors.New("invalid destination address")
	errCannotRoute                   = errors.New("cannot route, dropping pkt")
	errEmptyValue                    = errors.New("empty value")
	errMalformedPath                 = errors.New("malformed path content")
	errModifyExisting                = errors.New("modifying a running dataplane is not allowed")
	errUnsupportedPathType           = errors.New("unsupported path type")
	errUnsupportedPathTypeNextHeader = errors.New("unsupported combination")
	errNoSuchUnderlay                = errors.New("no such underlay provider")
	errNoBFDSessionFound             = errors.New("no BFD session was found")
	errPeeringEmptySeg0              = errors.New("zero-length segment[0] in peering path")
	errPeeringEmptySeg1              = errors.New("zero-length segment[1] in peering path")
	errPeeringNonemptySeg2           = errors.New("non-zero-length segment[2] in peering path")
	errBFDSessionDown                = errors.New("bfd session down")
	errExpiredHop                    = errors.New("expired hop")
	errIngressInterfaceInvalid       = errors.New("ingress interface invalid")
	errMacVerificationFailed         = errors.New("MAC verification failed")
	errBadPacketSize                 = errors.New("bad packet size")

	// zeroBuffer will be used to reset the Authenticator option in the
	// scionPacketProcessor.OptAuth
	zeroBuffer = make([]byte, 16)

	metrics = NewMetrics() // There can be only one currently.
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

// newDataPlane returns a zero-valued data plane structure. The difference between
// that and &dataPlane{} is that there are no nil pointers (i.e. maps are empty but exist and some
// key objects like the underlay provider have been created) except for such things that cannot be
// initialized at the beginning (i.e. packet pool and macFactory). Do not use a true zero valued
// struct for anything. Support for lazy initialization has been removed. It was much too
// bug-friendly.
func newDataPlane(runConfig RunConfig, authSCMP bool) *dataPlane {
	x := makeDataPlane(runConfig, authSCMP)
	return &x
}

// makeDataPlane returns a zero-valued data plane structure. This is the same as newDataPlane
// but returns by value to facilitate the initialization of composed structs without an temporary
// copy.
func makeDataPlane(runConfig RunConfig, authSCMP bool) dataPlane {
	// So many tests need the udpip underlay provider instantiated early that we do it here rather
	// than in AddInternalInterface. Currently there can be no dataplane without the udpip provider,
	// therefore not having a registered factory for it is a panicable offsense. We have no plan B.

	return dataPlane{
		underlays: map[string]UnderlayProvider{
			"udpip": underlayProviders["udpip"](
				runConfig.BatchSize,
				runConfig.SendBufferSize,
				runConfig.ReceiveBufferSize,
			),
		},
		Metrics:                        metrics,
		ExperimentalSCMPAuthentication: authSCMP,
		RunConfig:                      runConfig,
	}
}

// setRunning() Configures the running state of the data plane to true. setRunning() is called once
// the dataplane is finished initializing and is ready to process packets.
func (d *dataPlane) setRunning() {
	d.running.Store(true)
}

// setStopping() Configures the running state of the data plane to false. This should not be called
// during the dataplane initialization. Calling this before initialization starts has no effect.
func (d *dataPlane) setStopping() {
	d.running.Store(false)
}

// isRunning() Indicates the running state of the data plane. If true, the dataplane is initialized
// and ready to process or already processing packets. In this case some configuration changes are
// not permitted. If false, the data plane is not ready to process packets yet, or is shutting
// down.
func (d *dataPlane) isRunning() bool {
	return d.running.Load()
}

// Shutdown() causes the dataplane to stop accepting packets and then terminate. Note that
// in that case the router is committed to shutting down. There is no mechanism to restart it.
func (d *dataPlane) Shutdown() {
	d.mtx.Lock() // make sure we're not racing with initialization.
	defer d.mtx.Unlock()
	for _, u := range d.underlays {
		u.Stop()
	}
	d.setStopping()
}

// SetIA sets the local IA for the dataplane.
func (d *dataPlane) SetIA(ia addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.isRunning() {
		return errModifyExisting
	}
	if ia.IsZero() {
		return errEmptyValue
	}
	if !d.localIA.IsZero() {
		return errAlreadySet
	}
	d.localIA = ia
	return nil
}

// SetKey sets the key used for MAC verification. The key provided here should
// already be derived as in scrypto.HFMacFactory.
func (d *dataPlane) SetKey(key []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.isRunning() {
		return errModifyExisting
	}
	if len(key) == 0 {
		return errEmptyValue
	}
	if d.macFactory != nil {
		return errAlreadySet
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

func (d *dataPlane) SetPortRange(start, end uint16) {
	d.dispatchedPortStart = start
	d.dispatchedPortEnd = end
}

// AddInternalInterface sets the interface the data-plane will use to send/receive traffic in the
// local AS. This can only be called once; future calls will return an error. This can only be
// called on a not yet running dataplane. Note that localHost is a SCION host address. It currently
// mirrors localAddr, which is the address on the local underlay network, but that could change
// in the future. This is not the router's decision.
func (d *dataPlane) AddInternalInterface(localHost addr.Host, provider, localAddr string) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.isRunning() {
		return errModifyExisting
	}
	if d.interfaces[0] != nil {
		return serrors.JoinNoStack(errAlreadySet, nil, "ifID", 0)
	}

	// The internal network underlay is instantiated at construction to simplify some tests. Things
	// would become a lot more complicated if we ever supported multiple internal underlays.
	internalUnderlay := d.underlays[provider]
	if internalUnderlay == nil {
		return serrors.JoinNoStack(errNoSuchUnderlay, nil, "provider", provider)
	}
	iMetrics := newInterfaceMetrics(d.Metrics, 0, d.localIA, "", d.neighborIAs[0])
	lk, err := internalUnderlay.NewInternalLink(localAddr, d.RunConfig.BatchSize, iMetrics)
	if err != nil {
		return err
	}
	d.interfaces[0] = lk
	d.numInterfaces++
	d.localHost = localHost

	return nil
}

// AddExternalInterface adds the inter AS connection for the given interface ID.
// If a connection for the given ID is already set this method will return an
// error. This can only be called on a not yet running dataplane.
func (d *dataPlane) AddExternalInterface(
	ifID uint16, link control.LinkInfo, localHost, remoteHost addr.Host,
) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.isRunning() {
		return errModifyExisting
	}
	bfd, err := d.newExternalInterfaceBFD(ifID, link, localHost, remoteHost)
	if err != nil {
		return serrors.Wrap("adding external BFD", err, "if_id", ifID)
	}
	if d.interfaces[ifID] != nil {
		return serrors.JoinNoStack(errAlreadySet, nil, "ifID", ifID)
	}
	if link.Remote.Addr == "" {
		return errEmptyValue
	}

	underlay, instantiated := d.underlays[link.Provider]
	if !instantiated {
		underlayProvider, exists := underlayProviders[link.Provider]
		if !exists {
			panic(fmt.Sprintf("no provider for underlay: %q", link.Provider))
		}
		underlay = underlayProvider(
			d.RunConfig.BatchSize,
			d.RunConfig.SendBufferSize,
			d.RunConfig.ReceiveBufferSize,
		)
		d.underlays[link.Provider] = underlay
	}
	d.linkTypes[ifID] = link.LinkTo

	iMetrics := newInterfaceMetrics(d.Metrics, ifID, d.localIA, "", d.neighborIAs[ifID])
	lk, err := underlay.NewExternalLink(
		d.RunConfig.BatchSize,
		bfd,
		link.Local.Addr,
		link.Remote.Addr,
		ifID,
		iMetrics)
	if err != nil {
		return err
	}
	d.interfaces[ifID] = lk
	d.numInterfaces++
	return nil
}

// AddNeighborIA adds the neighboring IA for a given interface ID. If an IA for
// the given ID is already set, this method will return an error. This can only
// be called on a not yet running dataplane.
func (d *dataPlane) AddNeighborIA(ifID uint16, remote addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.isRunning() {
		return errModifyExisting
	}
	if remote.IsZero() {
		return errEmptyValue
	}
	if !d.neighborIAs[ifID].IsZero() {
		return serrors.JoinNoStack(errAlreadySet, nil, "ifID", ifID)
	}
	d.neighborIAs[ifID] = remote
	return nil
}

// newExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *dataPlane) newExternalInterfaceBFD(
	ifID uint16, link control.LinkInfo, localHost, remoteHost addr.Host,
) (*bfd.Session, error) {
	if *link.BFD.Disable {
		return nil, nil
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{
			"interface":       fmt.Sprint(ifID),
			"isd_as":          d.localIA.String(),
			"neighbor_isd_as": link.Remote.IA.String(),
		}
		m = bfd.Metrics{
			Up:              d.Metrics.InterfaceUp.With(labels),
			StateChanges:    d.Metrics.BFDInterfaceStateChanges.With(labels),
			PacketsSent:     d.Metrics.BFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.BFDPacketsReceived.With(labels),
		}
	}
	s, err := newBFDSend(d, link, localHost, remoteHost, ifID, false, d.macFactory())
	if err != nil {
		return nil, err
	}
	return bfd.NewSession(s, link.BFD, m)
}

// getInterfaceState checks if there is a bfd session for the input interfaceID and
// returns InterfaceUp if the relevant BFDSession state is up, or if there is no BFD
// session. Otherwise, it returns InterfaceDown.
func (d *dataPlane) getInterfaceState(ifID uint16) control.InterfaceState {
	if link := d.interfaces[ifID]; link != nil && !link.IsUp() {
		return control.InterfaceDown
	}
	return control.InterfaceUp
}

// AddSvc adds the address for the given service. This can be called multiple
// times for the same service, with the address added to the list of addresses
// that provide the service.
func (d *dataPlane) AddSvc(svc addr.SVC, host addr.Host, port uint16) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	// TODO: underlay choice should really be "interfaces[0].provider"
	if err := d.underlays["udpip"].AddSvc(svc, host, port); err != nil {
		return err
	}
	if d.Metrics != nil {
		labels := serviceLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(1)
	}
	return nil
}

// DelSvc deletes the address for the given service.
func (d *dataPlane) DelSvc(svc addr.SVC, host addr.Host, port uint16) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	// TODO: underlay choice should really be "interfaces[0].provider"
	if err := d.underlays["udpip"].DelSvc(svc, host, port); err != nil {
		return err
	}
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
func (d *dataPlane) AddNextHop(
	ifID uint16,
	link control.LinkInfo,
	localHost, remoteHost addr.Host,
) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	if d.isRunning() {
		return errModifyExisting
	}
	bfd, err := d.newNextHopBFD(ifID, link, localHost, remoteHost)
	if err != nil {
		return serrors.Wrap("adding next hop BFD", err, "if_id", ifID)
	}
	if d.interfaces[ifID] != nil {
		return serrors.JoinNoStack(errAlreadySet, nil, "ifID", ifID)
	}
	if link.Remote.Addr == "" {
		return errEmptyValue
	}
	underlay, instantiated := d.underlays[link.Provider]
	if !instantiated {
		underlayProvider, exists := underlayProviders[link.Provider]
		if !exists {
			panic(fmt.Sprintf("no provider for underlay: %q", link.Provider))
		}
		underlay = underlayProvider(
			d.RunConfig.BatchSize,
			d.RunConfig.SendBufferSize,
			d.RunConfig.ReceiveBufferSize,
		)
		d.underlays[link.Provider] = underlay
	}
	d.linkTypes[ifID] = link.LinkTo

	// Note that a link to the same sibling router might already exist. If so, it will be
	// returned instead of creating a new one. As a result, the bfd session and metrics will be
	// ignored and simply garbage collected.
	iMetrics := newInterfaceMetrics(
		d.Metrics, ifID, d.localIA, link.Remote.Addr, d.neighborIAs[ifID])
	lk, err := underlay.NewSiblingLink(
		d.RunConfig.BatchSize, bfd, link.Local.Addr, link.Remote.Addr, iMetrics)
	if err != nil {
		return err
	}
	d.interfaces[ifID] = lk
	d.numInterfaces++
	return nil
}

// AddNextHopBFD adds the BFD session for the next hop address.
func (d *dataPlane) newNextHopBFD(
	ifID uint16,
	link control.LinkInfo,
	localHost, remoteHost addr.Host,
) (*bfd.Session, error) {
	if *link.BFD.Disable {
		return nil, nil
	}
	var m bfd.Metrics
	if d.Metrics != nil {
		labels := prometheus.Labels{"isd_as": d.localIA.String(), "sibling": link.Instance}
		m = bfd.Metrics{
			Up:              d.Metrics.SiblingReachable.With(labels),
			StateChanges:    d.Metrics.SiblingBFDStateChanges.With(labels),
			PacketsSent:     d.Metrics.SiblingBFDPacketsSent.With(labels),
			PacketsReceived: d.Metrics.SiblingBFDPacketsReceived.With(labels),
		}
	}

	s, err := newBFDSend(d, link, localHost, remoteHost, ifID, true, d.macFactory())
	if err != nil {
		return nil, err
	}
	return bfd.NewSession(s, link.BFD, m)
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
	ReceiveBufferSize     int
	SendBufferSize        int
}

func (d *dataPlane) Run(ctx context.Context) error {
	d.mtx.Lock()
	if d.numInterfaces == 0 {
		// Not stritcly an error but we really can't do anything; most maps aren't even allocated,
		// due to lazy initialization.
		return nil
	}

	// Start our custom /proc/pid/stat collector to export iowait time and (in the future) other
	// process-wide metrics that prometheus does not.
	err := processmetrics.Init()
	// we can live without these metrics. Just log the error.
	if err != nil {
		log.Error("Could not initialize processmetrics", "err", err)
	}

	numConnections := 0
	for _, u := range d.underlays {
		numConnections += u.NumConnections()
	}
	processorQueueSize := max(
		numConnections*d.RunConfig.BatchSize/d.RunConfig.NumProcessors,
		d.RunConfig.BatchSize,
	)
	d.initPacketPool(processorQueueSize)
	procQs, slowQs := d.initQueues(processorQueueSize)
	d.setRunning()
	for _, u := range d.underlays {
		u.Start(ctx, d.packetPool, procQs)
	}
	for i := 0; i < d.RunConfig.NumProcessors; i++ {
		go func(i int) {
			defer log.HandlePanic()
			d.runProcessor(i, procQs[i], slowQs[i%d.RunConfig.NumSlowPathProcessors])
		}(i)
	}
	for i := 0; i < d.RunConfig.NumSlowPathProcessors; i++ {
		go func(i int) {
			defer log.HandlePanic()
			d.runSlowPathProcessor(i, slowQs[i])
		}(i)
	}

	d.mtx.Unlock()
	<-ctx.Done()
	return nil
}

// initializePacketPool calculates the size of the packet pool based on the
// current dataplane settings and allocates all the buffers
func (d *dataPlane) initPacketPool(processorQueueSize int) {
	// collect pool size and headroom reqs
	poolSize := d.numInterfaces*d.RunConfig.BatchSize +
		(d.RunConfig.NumProcessors+d.RunConfig.NumSlowPathProcessors)*(processorQueueSize+1) +
		d.numInterfaces*2*d.RunConfig.BatchSize
	headroom := 0
	for _, u := range d.underlays {
		h := u.Headroom()
		if headroom < h {
			headroom = h
		}
	}
	d.underlayHeadroom = headroom

	// We round-up the minimum headroom generously so that the extra room is sufficient to allow the
	// quoting of most packets by SCMP cheaply (that is, without moving the bytes). Our packet
	// buffers are sized at 9000 bytes while in most cases the interface MTU is lower.
	if headroom < minHeadroom {
		headroom = minHeadroom
	}
	log.Debug("Initialize packet pool", "poolSize", poolSize, "headroom", headroom)
	d.packetPool = makePacketPool(poolSize, headroom)
	pktBuffers := make([][bufSize]byte, poolSize)
	pktStructs := make([]Packet, poolSize)
	for i := 0; i < poolSize; i++ {
		d.packetPool.Put(pktStructs[i].init(&pktBuffers[i]))
	}
}

// initializes the processing routines and queues
func (d *dataPlane) initQueues(processorQueueSize int) ([]chan *Packet, []chan *Packet) {
	procQs := make([]chan *Packet, d.RunConfig.NumProcessors)
	for i := 0; i < d.RunConfig.NumProcessors; i++ {
		procQs[i] = make(chan *Packet, processorQueueSize)
	}
	slowQs := make([]chan *Packet, d.RunConfig.NumSlowPathProcessors)
	for i := 0; i < d.RunConfig.NumSlowPathProcessors; i++ {
		slowQs[i] = make(chan *Packet, processorQueueSize)
	}
	return procQs, slowQs
}

func (d *dataPlane) runProcessor(id int, q <-chan *Packet, slowQ chan<- *Packet) {
	log.Debug("Initialize processor with", "id", id)
	processor := newPacketProcessor(d)
	for d.isRunning() {
		p, ok := <-q
		if !ok {
			continue
		}
		disp := processor.processPkt(p)

		sc := ClassOfSize(len(p.RawPacket))
		metrics := p.Link.Metrics()
		metrics[sc].ProcessedPackets.Inc()

		switch disp {
		case pForward:
			// Normal processing proceeds.
		case pSlowPath:
			// Not an error, processing continues on the slow path.
			select {
			case slowQ <- p:
			default:
				metrics[sc].DroppedPacketsBusySlowPath.Inc()
				d.packetPool.Put(p)
			}
			continue
		case pDone: // Packets that don't need more processing (e.g. BFD)
			d.packetPool.Put(p)
			continue
		case pDiscard: // Everything else
			metrics[sc].DroppedPacketsInvalid.Inc()
			d.packetPool.Put(p)
			continue
		default: // Newly added dispositions need to be handled.
			log.Debug("Unknown packet disposition", "disp", disp)
			d.packetPool.Put(p)
			continue
		}
		fwLink := d.interfaces[p.egress]
		if fwLink == nil {
			log.Debug("Error determining forwarder. Egress is invalid", "egress", p.egress)
			d.packetPool.Put(p)
			metrics[sc].DroppedPacketsInvalid.Inc()
			continue
		}
		if !fwLink.Send(p) {
			d.packetPool.Put(p)
			metrics[sc].DroppedPacketsBusyForwarder.Inc()
		}
	}
}

func (d *dataPlane) runSlowPathProcessor(id int, q <-chan *Packet) {
	log.Debug("Initialize slow-path processor with", "id", id)
	processor := newSlowPathProcessor(d)
	for d.isRunning() {
		p, ok := <-q
		if !ok {
			continue
		}
		err := processor.processPacket(p)
		if err != nil {
			log.Debug("Error processing packet", "err", err)
			sc := ClassOfSize(len(p.RawPacket))
			p.Link.Metrics()[sc].DroppedPacketsInvalid.Inc()
			d.packetPool.Put(p)
			continue
		}
		// All slowpath packets are responses to the sender. Therefore, the egress link is always
		// the ingress link. egress = ingress is, in theory, not sufficient (since it is zero
		// for sibling ingress links).
		egressLink := p.Link
		if egressLink == nil {
			// Someone tried to send a freshly made packet on the slow path?
			log.Debug("Error determining return link. No ingress link")
			d.packetPool.Put(p)
			continue
		}
		if !egressLink.Send(p) {
			d.packetPool.Put(p)
		}
	}
}

func newSlowPathProcessor(d *dataPlane) *slowPathPacketProcessor {
	p := &slowPathPacketProcessor{
		d:              d,
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
	d               *dataPlane
	pkt             *Packet
	ingressFromLink uint16 // This is the IfID associated with the ingress link, if any.
	scionLayer      slayers.SCION
	hbhLayer        slayers.HopByHopExtnSkipper
	e2eLayer        slayers.EndToEndExtnSkipper
	lastLayer       gopacket.DecodingLayer
	path            *scion.Raw

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
	p.path = nil
	p.ingressFromLink = 0
	p.hbhLayer = slayers.HopByHopExtnSkipper{}
	p.e2eLayer = slayers.EndToEndExtnSkipper{}
}

func (p *slowPathPacketProcessor) processPacket(pkt *Packet) error {
	var err error
	p.reset()
	p.pkt = pkt
	p.ingressFromLink = pkt.Link.IfID()

	p.lastLayer, err = decodeLayers(pkt.RawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return err
	}
	pathType := p.scionLayer.PathType
	switch pathType {
	case scion.PathType:
		var ok bool
		p.path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return errMalformedPath
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return errMalformedPath
		}
		p.path = epicPath.ScionPath
		if p.path == nil {
			return errMalformedPath
		}
	default:
		// unsupported path type
		return serrors.New("Path type not supported for slow-path", "type", pathType)
	}

	s := pkt.slowPathRequest
	switch s.spType {
	case slowPathRouterAlertIngress: // Traceroute
		return p.handleSCMPTraceRouteRequest(p.ingressFromLink)
	case slowPathRouterAlertEgress: // Traceroute
		return p.handleSCMPTraceRouteRequest(p.pkt.egress)
	default: // SCMP
		var layer gopacket.SerializableLayer
		scmpType := slayers.SCMPType(s.spType)
		switch scmpType {
		case slayers.SCMPTypeParameterProblem:
			layer = &slayers.SCMPParameterProblem{Pointer: s.pointer}
		case slayers.SCMPTypeDestinationUnreachable:
			layer = &slayers.SCMPDestinationUnreachable{}
		case slayers.SCMPTypeExternalInterfaceDown:
			layer = &slayers.SCMPExternalInterfaceDown{
				IA:   p.d.localIA,
				IfID: uint64(p.pkt.egress),
			}
		case slayers.SCMPTypeInternalConnectivityDown:
			layer = &slayers.SCMPInternalConnectivityDown{
				IA:      p.d.localIA,
				Ingress: uint64(p.ingressFromLink),
				Egress:  uint64(p.pkt.egress),
			}
		default:
			panic(fmt.Errorf("unsupported slow-path type: %d", scmpType))
		}
		return p.packSCMP(scmpType, s.code, layer, true)
	}
}

func newPacketProcessor(d *dataPlane) *scionPacketProcessor {
	p := &scionPacketProcessor{
		d:              d,
		mac:            d.macFactory(),
		macInputBuffer: make([]byte, max(path.MACBufferSize, libepic.MACBufferSize)),
	}
	p.scionLayer.RecyclePaths()
	return p
}

func (p *scionPacketProcessor) reset() error {
	p.pkt = nil
	p.ingressFromLink = 0
	// p.scionLayer // cannot easily be reset
	p.path = nil
	p.hopField = path.HopField{}
	p.infoField = path.InfoField{}
	p.effectiveXover = false
	p.peering = false
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

func (p *scionPacketProcessor) processPkt(pkt *Packet) disposition {
	if err := p.reset(); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt = pkt
	p.ingressFromLink = pkt.Link.IfID()

	// parse SCION header and skip extensions;
	var err error
	p.lastLayer, err = decodeLayers(pkt.RawPacket, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	pld := p.lastLayer.LayerPayload()

	pathType := p.scionLayer.PathType
	switch pathType {
	case empty.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			return p.processBFD(pld)
		}
		return errorDiscard("error", errUnsupportedPathTypeNextHeader)

	case onehop.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			_, ok := p.scionLayer.Path.(*onehop.Path)
			if !ok {
				return errorDiscard("error", errMalformedPath)
			}
			return p.processBFD(pld)
		}
		return p.processOHP()
	case scion.PathType:
		return p.processSCION()
	case epic.PathType:
		return p.processEPIC()
	default:
		return errorDiscard("error", errUnsupportedPathType)
	}
}

func (p *scionPacketProcessor) processBFD(data []byte) disposition {
	session := p.pkt.Link.BFDSession()
	if session == nil {
		return errorDiscard("error", errNoBFDSessionFound)
	}
	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return errorDiscard("error", err)
	}
	session.ReceiveMessage(bfd)
	return pDone // All's fine. That packet's journey ends here.
}

func (p *scionPacketProcessor) processSCION() disposition {
	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", errMalformedPath)
	}
	return p.process()
}

func (p *scionPacketProcessor) processEPIC() disposition {
	epicPath, ok := p.scionLayer.Path.(*epic.Path)
	if !ok {
		return errorDiscard("error", errMalformedPath)
	}

	p.path = epicPath.ScionPath
	if p.path == nil {
		return errorDiscard("error", errMalformedPath)
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
	d               *dataPlane    // The dataplane instance that initiated this processor.
	pkt             *Packet       // Packet currently being processed by this processor.
	ingressFromLink uint16        // IfID associated with the ingress link, if any.
	mac             hash.Hash     // hasher for the MAC computation.
	scionLayer      slayers.SCION // scionLayer is the SCION gopacket layer.
	hbhLayer        slayers.HopByHopExtnSkipper
	e2eLayer        slayers.EndToEndExtnSkipper
	lastLayer       gopacket.DecodingLayer // Last parsed layer: &scionLayer, &hbhLayer or &e2eLayer
	path            *scion.Raw             // Raw SCION path. Will be set during processing.
	hopField        path.HopField          // Current hop field, updated during processing.
	infoField       path.InfoField         // Current info field, updated during processing.
	effectiveXover  bool                   // Whether a segment cross-over was done.
	peering         bool                   // Whether the current hop field is a peering hop field.
	cachedMac       []byte                 // Full MAC. For a Xover, that of the down segment.
	macInputBuffer  []byte                 // Reusable buffer for MAC computation.
	bfdLayer        layers.BFD             // Reusable buffer for parsing BFD messages
}

type slowPathType int8

const (
	slowPathSCMP               slowPathType = 0 // >=0 means it is an SCMP error
	slowPathRouterAlertIngress slowPathType = -1
	slowPathRouterAlertEgress  slowPathType = -2
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
			return serrors.Wrap("decoding SCMP layer", err)
		}
		if !scmpLayer.TypeCode.InfoMsg() {
			return serrors.New("SCMP error for SCMP error pkt -> DROP")
		}
	}

	if err := p.prepareSCMP(typ, code, scmpP, isError); err != nil {
		return err
	}

	// We're about to send a packet that has little to do with the one we received.
	// The original traffic type, if one had been set, no-longer applies.
	p.pkt.trafficType = ttOther

	// The packet does not need any addressing: the slowpath processor always sends the packet back
	// on the link that delivered it (p.pkt.link). In case the link is an unconnected one, it did
	// set p.pkt.RemoteAddr on the way in; so it's good to go.

	return nil
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
		return errorDiscard("error", errMalformedPath)
	}
	if !p.path.CurrINFMatchesCurrHF() {
		return errorDiscard("error", errMalformedPath)
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
	log.Debug("SCMP response", "cause", errExpiredHop,
		"cons_dir", p.infoField.ConsDir, "if_id", p.ingressFromLink,
		"curr_inf", p.path.PathMeta.CurrINF, "curr_hf", p.path.PathMeta.CurrHF)
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodePathExpired,
		pointer: p.currentHopPointer(),
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
	if p.ingressFromLink != 0 && p.ingressFromLink != hdrIngressID {
		log.Debug("SCMP response", "cause", errIngressInterfaceInvalid,
			"pkt_ingress", hdrIngressID, "router_ingress", p.ingressFromLink)
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    errCode,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) validateSrcDstIA() disposition {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.ingressFromLink == 0 {
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
	log.Debug("SCMP response", "cause", errInvalidSrcIA)
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidSourceAddress,
		pointer: uint16(slayers.CmnHdrLen + addr.IABytes),
	}
	return pSlowPath
}

// invalidDstIA is a helper to return an SCMP error for an invalid DstIA.
func (p *scionPacketProcessor) respInvalidDstIA() disposition {
	log.Debug("SCMP response", "cause", errInvalidDstIA)
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidDestinationAddress,
		pointer: uint16(slayers.CmnHdrLen),
	}
	return pSlowPath
}

// validateTransitUnderlaySrc prevents malicious end hosts in the local AS from bypassing the SrcIA
// checks by disguising packets as transit traffic: each sibling link ensures that the src address
// of a packet is that of their expected sibling router. But we must verify that the right sibling
// link was used in the first place.
func (p *scionPacketProcessor) validateTransitUnderlaySrc() disposition {
	if p.path.IsFirstHop() || p.ingressFromLink != 0 {
		// Locally originated traffic, or came in via an external link. Not our concern.
		return pForward
	}
	pktIngressID := p.ingressInterface()        // Where this was *supposed* to enter the AS
	ingressLink := p.d.interfaces[pktIngressID] // Our own link to *that* sibling router

	// Is that the link that the packet came through (e.g. not the internal link)? The
	// comparison should be cheap. Links are implemented by pointers.
	if ingressLink != p.pkt.Link {
		// Drop
		return errorDiscard("error", errInvalidSrcAddrForTransit)
	}
	return pForward
}

// Validates the egress interface referenced by the current hop. This is not called for
// packets to be delivered to the local AS, so pkt.egress is never 0.
// If pkt.Ingress is zero, the packet can be coming from either a local end-host or a
// sibling router. In either of these cases, it must be leaving via a locally owned external
// interface (i.e. it can't be going to a sibling router or to a local end-host). On the other
// hand, a packet coming directly from another AS can be going anywhere: local delivery,
// to another AS directly, or via a sibling router.
func (p *scionPacketProcessor) validateEgressID() disposition {
	egressID := p.pkt.egress
	egressLink := p.d.interfaces[egressID]

	// egress interface must be a known interface
	// egress is never the internal interface (already checked)
	// packet coming from internal interface, must go to an external interface
	// Note that, for now, ingress == 0 is also true for sibling interfaces. That might change.
	if egressLink == nil || (p.ingressFromLink == 0 && egressLink.Scope() == Sibling) {
		errCode := slayers.SCMPCodeUnknownHopFieldEgress
		if !p.infoField.ConsDir {
			errCode = slayers.SCMPCodeUnknownHopFieldIngress
		}
		log.Debug("SCMP response", "cause", errCannotRoute)
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    errCode,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}

	ingressLT, egressLT := p.d.linkTypes[p.ingressFromLink], p.d.linkTypes[egressID]
	if !p.effectiveXover {
		// No check required if the packet is received from an internal interface because that
		// check was done by the ingress router.

		// This case applies to peering hops as a peering hop isn't an effective
		// cross-over (eventhough it is a segment change).
		// Check that the interface pair is valid within a single segment.
		switch {
		case p.ingressFromLink == 0:
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
			log.Debug("SCMP response", "cause", errCannotRoute,
				"ingress_id", p.ingressFromLink, "ingress_type", ingressLT,
				"egress_id", egressID, "egress_type", egressLT)
			p.pkt.slowPathRequest = slowPathRequest{
				spType:  slowPathType(slayers.SCMPTypeParameterProblem),
				code:    slayers.SCMPCodeInvalidPath, // XXX(matzf) new code InvalidHop?,
				pointer: p.currentHopPointer(),
			}
			return pSlowPath
		}
	}

	// Check that the interface pair is valid on a segment switch.
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
		log.Debug("SCMP response", "cause", errCannotRoute,
			"ingress_id", p.ingressFromLink, "ingress_type", ingressLT,
			"egress_id", egressID, "egress_type", egressLT)
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    slayers.SCMPCodeInvalidSegmentChange,
			pointer: p.currentInfoPointer(),
		}
		return pSlowPath
	}
}

func (p *scionPacketProcessor) updateNonConsDirIngressSegID() disposition {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// For packets destined to peer links this shouldn't be updated.
	if !p.infoField.ConsDir && p.ingressFromLink != 0 && !p.peering {
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
		log.Debug("SCMP response", "cause", errMacVerificationFailed,
			"expected", fullMac[:path.MacLen],
			"actual", p.hopField.Mac[:path.MacLen],
			"cons_dir", p.infoField.ConsDir,
			"if_id", p.ingressFromLink, "curr_inf", p.path.PathMeta.CurrINF,
			"curr_hf", p.path.PathMeta.CurrHF, "seg_id", p.infoField.SegID)
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    slayers.SCMPCodeInvalidHopFieldMAC,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC does not need to recalculate it.
	p.cachedMac = fullMac

	return pForward
}

func (p *scionPacketProcessor) resolveInbound() disposition {
	// The internal link is by definition unbound; we need to update the destination.
	err := p.d.resolveLocalDst(p.pkt, p.scionLayer, p.lastLayer)

	switch err {
	case nil:
		return pForward
	case ErrNoSVCBackend:
		log.Debug("SCMP response", "cause", err)
		p.pkt.slowPathRequest = slowPathRequest{
			spType: slowPathType(slayers.SCMPTypeDestinationUnreachable),
			code:   slayers.SCMPCodeNoRoute,
		}
		return pSlowPath
	case errInvalidDstAddr, ErrUnsupportedV4MappedV6Address, ErrUnsupportedUnspecifiedAddress:
		log.Debug("SCMP response", "cause", err)
		p.pkt.slowPathRequest = slowPathRequest{
			spType: slowPathType(slayers.SCMPTypeParameterProblem),
			code:   slayers.SCMPCodeInvalidDestinationAddress,
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
	egressLink := p.d.interfaces[egressID]
	if !egressLink.IsUp() {
		log.Debug("SCMP response", "cause", errBFDSessionDown)
		if egressLink.Scope() != External {
			p.pkt.slowPathRequest = slowPathRequest{
				spType: slowPathType(slayers.SCMPTypeInternalConnectivityDown),
				code:   0,
			}
		} else {
			p.pkt.slowPathRequest = slowPathRequest{
				spType: slowPathType(slayers.SCMPTypeExternalInterfaceDown),
				code:   0,
			}
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) handleIngressRouterAlert() disposition {
	if p.ingressFromLink == 0 {
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
		spType: slowPathRouterAlertIngress,
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
	if p.d.interfaces[p.pkt.egress].Scope() != External {
		// the egress router is not this one.
		return pForward
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathRouterAlertEgress,
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
	log.Debug("SCMP response", "cause", errBadPacketSize, "header", p.scionLayer.PayloadLen,
		"actual", len(p.scionLayer.Payload))
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeInvalidPacketSize,
		pointer: 0,
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
		err = ErrUnsupportedV4MappedV6Address
	}
	if err == nil {
		return pForward
	}

	log.Debug("SCMP response", "cause", err)
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathType(slayers.SCMPTypeParameterProblem),
		code:   slayers.SCMPCodeInvalidSourceAddress,
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
	if p.d.interfaces[egressID].Scope() == External {
		// Not ASTransit in
		if disp := p.processEgress(); disp != pForward {
			return disp
		}
		// Finish deciding the trafficType...
		var tt trafficType
		if p.scionLayer.SrcIA == p.d.localIA {
			// Pure outbound
			tt = ttOut
		} else if p.ingressFromLink == 0 {
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
	// We already know the egressID is valid. The packet can go straight to forwarding.
	p.pkt.trafficType = ttInTransit
	return pForward
}

func (p *scionPacketProcessor) processOHP() disposition {
	s := p.scionLayer
	ohp, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return errorDiscard("error", errMalformedPath)
	}
	if !ohp.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return errorDiscard("error", errMalformedPath)
	}

	// OHP leaving our IA
	if p.ingressFromLink == 0 {
		if !p.d.localIA.Equal(s.SrcIA) {
			// TODO parameter problem -> invalid path
			return errorDiscard("error", errCannotRoute)
		}
		neighborIA := p.d.neighborIAs[ohp.FirstHop.ConsEgress]
		if neighborIA.IsZero() {
			// TODO parameter problem invalid interface
			return errorDiscard("error", errCannotRoute)
		}
		if !neighborIA.Equal(s.DstIA) {
			return errorDiscard("error", errCannotRoute)
		}
		mac := path.MAC(p.mac, ohp.Info, ohp.FirstHop, p.macInputBuffer[:path.MACBufferSize])
		if subtle.ConstantTimeCompare(ohp.FirstHop.Mac[:], mac[:]) == 0 {
			// TODO parameter problem -> invalid MAC
			return errorDiscard("error", errMacVerificationFailed)
		}
		ohp.Info.UpdateSegID(ohp.FirstHop.Mac)

		if err := updateSCIONLayer(p.pkt.RawPacket, s); err != nil {
			return errorDiscard("error", err)
		}
		p.pkt.egress = ohp.FirstHop.ConsEgress
		return pForward
	}

	// OHP entering our IA
	if !p.d.localIA.Equal(s.DstIA) {
		return errorDiscard("error", errCannotRoute)
	}
	neighborIA := p.d.neighborIAs[p.ingressFromLink]
	if !neighborIA.Equal(s.SrcIA) {
		return errorDiscard("error", errCannotRoute)
	}

	ohp.SecondHop = path.HopField{
		ConsIngress: p.ingressFromLink,
		ExpTime:     ohp.FirstHop.ExpTime,
	}
	// XXX(roosd): Here we leak the buffer into the SCION packet header.
	// This is okay because we do not operate on the buffer or the packet
	// for the rest of processing.
	ohp.SecondHop.Mac = path.MAC(p.mac, ohp.Info, ohp.SecondHop,
		p.macInputBuffer[:path.MACBufferSize])

	if err := updateSCIONLayer(p.pkt.RawPacket, s); err != nil {
		return errorDiscard("error", err)
	}
	err := p.d.resolveLocalDst(p.pkt, s, p.lastLayer)
	if err != nil {
		return errorDiscard("error", err)
	}

	return pForward
}

// resolveLocalDst updates the packet's remote address (from then on, its destination) by
// translating the given SCION address (host or service) into an underlay address.
func (d *dataPlane) resolveLocalDst(
	packet *Packet,
	s slayers.SCION,
	lastLayer gopacket.DecodingLayer,
) error {
	a, err := s.DstAddr()
	if err != nil {
		return errInvalidDstAddr
	}

	p := uint16(0)
	if a.Type() == addr.HostTypeIP {
		// In this case, we must find the destination SCION port so we have a chance to dispatch to
		// to the UDP port of the same number directly instead of going through the dispatcher.
		// It's our job to figure that; the underlay doesn't know the SCION header.
		p, err = d.dstScionPort(lastLayer)
		if err != nil {
			return err
		}
	}

	// Let the internal (it better be) link resolve the destination to an underlay address.
	return d.interfaces[packet.egress].Resolve(packet, a, p)
}

func (d *dataPlane) dstScionPort(
	lastLayer gopacket.DecodingLayer,
) (uint16, error) {
	// Parse UPD port and rewrite underlay IP/UDP port
	l4Type := nextHdr(lastLayer)
	port := uint16(topology.EndhostPort)

	switch l4Type {
	case slayers.L4UDP:
		if len(lastLayer.LayerPayload()) < 8 {
			// TODO(JordiSubira): Treat this as a parameter problem
			return 0, serrors.New("SCION/UDP header len too small", "length",
				len(lastLayer.LayerPayload()))
		}
		port = binary.BigEndian.Uint16(lastLayer.LayerPayload()[2:])
	case slayers.L4TCP:
		if len(lastLayer.LayerPayload()) < 20 {
			// TODO: Treat this as a parameter problem
			return 0, serrors.New("SCION/TCP header len too small", "length",
				len(lastLayer.LayerPayload()))
		}
		port = binary.BigEndian.Uint16(lastLayer.LayerPayload()[2:])
	case slayers.L4SCMP:
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return 0, serrors.Wrap("decoding SCMP layer for extracting endhost dst port", err)
		}
		port, err = getDstPortSCMP(&scmpLayer)
		if err != nil {
			// TODO(JordiSubira): Treat this as a parameter problem.
			return 0, serrors.Wrap("getting dst port from SCMP message", err)
		}
	default:
		log.Debug("msg", "protocol", l4Type)
	}
	return port, nil
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

// updateSCIONLayer rewrites the SCION header at the start of the given raw packet buffer; replacing
// it with the serialization of the given new SCION header. This works only if the new header is of
// the same size as the old one. This function has no knowledge of the actual size of the headers;
// it only ensures that the new one ends exactly where the old one did. It is possible to use this
// function to replace a header with a smaller one; but the RawPacket's slice must be fixed
// afterwards (and the preceding headers, if any).
func updateSCIONLayer(rawPkt []byte, s slayers.SCION) error {
	payloadOffset := len(rawPkt) - len(s.LayerPayload())

	// Prepends must go just before payload. (and any Append will wreck it)
	serBuf := newSerializeProxyStart(rawPkt, payloadOffset)
	return s.SerializeTo(&serBuf, gopacket.SerializeOptions{})
}

type bfdSend struct {
	dataPlane *dataPlane
	name      string // for logs
	ifID      uint16
	scn       *slayers.SCION
	ohp       *onehop.Path
	mac       hash.Hash
	macBuffer []byte
}

// newBFDSend creates and initializes a BFD Sender
func newBFDSend(
	d *dataPlane,
	link control.LinkInfo,
	localHost, remoteHost addr.Host,
	ifID uint16,
	isIntraAS bool,
	mac hash.Hash,
) (*bfdSend, error) {
	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4BFD,
		SrcIA:        link.Local.IA,
	}
	if err := scn.SetSrcAddr(localHost); err != nil {
		panic(err)
	}
	if err := scn.SetDstAddr(remoteHost); err != nil {
		panic(err)
	}
	if ifID == 0 {
		// There is no reason to support this any more.
		panic("Sending BFD packets on the internal link")
	}
	var ohp *onehop.Path
	if isIntraAS {
		scn.PathType = empty.PathType
		scn.Path = &empty.Path{}
		scn.DstIA = scn.SrcIA
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
		scn.DstIA = link.Remote.IA
	}

	// bfdSend includes a reference to the dataplane. In general this must not be used until the
	// dataplane is running. This is ensured by the fact that bfdSend objects are owned by bfd
	// sessions, which are started by dataplane.Run() itself.

	return &bfdSend{
		dataPlane: d,
		name:      link.Remote.Addr,
		ifID:      ifID,
		scn:       scn,
		ohp:       ohp,
		mac:       mac,
		macBuffer: make([]byte, path.MACBufferSize),
	}, nil
}

func (b *bfdSend) String() string {
	return b.name
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

	p := b.dataPlane.packetPool.Get()

	serBuf := newSerializeProxy(p.RawPacket) // set for prepend-only by default. Perfect here.

	// serialized bytes lend directly into p.RawPacket (aligned at the end).
	err := gopacket.SerializeLayers(&serBuf, gopacket.SerializeOptions{FixLengths: true},
		b.scn, bfd)
	if err != nil {
		return err
	}

	// The useful part of the buffer is given by Bytes. We don't copy the bytes; just the slice's
	// metadata.
	p.RawPacket = serBuf.Bytes()

	// BfdControllers and fwQs are initialized from the same set of ifIDs. So not finding
	// the forwarding queue is an serious internal error. Let that panic.
	fwLink := b.dataPlane.interfaces[b.ifID]

	// BFD packets are always marked as priority.
	p.PriorityLabel = pr.WithPriority

	if !fwLink.Send(p) {
		// We do not care if some BFD packets get bounced under high load. If it becomes a problem,
		// the solution is do use BFD's demand-mode. To be considered in a future refactoring.
		b.dataPlane.packetPool.Put(p)
	}
	return err
}

func (p *slowPathPacketProcessor) prepareSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	isError bool,
) error {
	// *copy* and reverse path -- the original path should not be modified as this writes directly
	// back to rawPkt (quote).
	var path *scion.Raw
	pathType := p.scionLayer.Path.Type()
	switch pathType {
	case scion.PathType:
		var ok bool
		path, ok = p.scionLayer.Path.(*scion.Raw)
		if !ok {
			return serrors.JoinNoStack(errCannotRoute, nil, "details", "unsupported path type",
				"path type", pathType)
		}
	case epic.PathType:
		epicPath, ok := p.scionLayer.Path.(*epic.Path)
		if !ok {
			return serrors.JoinNoStack(errCannotRoute, nil, "details", "unsupported path type",
				"path type", pathType)
		}
		path = epicPath.ScionPath
	default:
		return serrors.JoinNoStack(errCannotRoute, nil, "details", "unsupported path type",
			"path type", pathType)

	}
	decPath, err := path.ToDecoded()
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "decoding raw path")
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := revPathTmp.(*scion.Decoded)

	peering, err := determinePeer(revPath.PathMeta, revPath.InfoFields[revPath.PathMeta.CurrINF])
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "peering cannot be determined")
	}

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() && !peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if err := revPath.IncPath(); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	// This is an SCMP response to pkt, so the egress link will be the ingress link.
	if p.pkt.Link.Scope() == External {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir && !peering {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := revPath.IncPath(); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "incrementing path for SCMP")
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

	if err := scionL.SetSrcAddr(p.d.localHost); err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "setting src addr")
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

	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var serBuf serializeProxy

	// First write the SCMP message only without the SCION header(s) to get a buffer that we can
	// feed to the MAC computation. If this is an error response, then it has to include a quote of
	// the packet at the end of the SCMP message.

	if isError {
		// There is headroom built into the packet buffer so we can wrap the whole packet into a new
		// one without copying it. We need to reclaim that headroom so we can prepend. We can figure
		// the current headroom, even if it was changed, by comparing the capacity of the slice with
		// our constant buffer size.
		quoteLen := len(p.pkt.RawPacket)
		headroom := len(p.pkt.buffer) - cap(p.pkt.RawPacket)
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len() +
			slayers.ScmpHeaderSize(scmpH.TypeCode.Type())

		if needsAuth {
			hdrLen += e2eAuthHdrLen
		}
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if quoteLen > maxQuoteLen {
			quoteLen = maxQuoteLen
		}
		// Now that we know the length, we can serialize the SCMP headers and the quoted packet. If
		// we don't fit in the headroom we copy the quoted packet to the end. We are required to
		// leave space for a worst-case underlay header too. TODO(multi_underlay): since we know
		// that this goes back via the link it came from, we could be content with leaving just
		// enough headroom for this specific underlay.
		if hdrLen+p.d.underlayHeadroom > headroom {
			// Not enough headroom. Pack at end.
			quote := p.pkt.RawPacket[:quoteLen]
			serBuf = newSerializeProxy(p.pkt.RawPacket)
			err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP, gopacket.Payload(quote))
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
		} else {
			// Serialize in front of the quoted packet. The quoted packet must be included in the
			// serialize buffer before we pack the SCMP header in from of it. AppendBytes will do
			// that; it exposes the underlying buffer but doesn't modify it.
			p.pkt.RawPacket = p.pkt.buffer[0:(quoteLen + headroom)]
			serBuf = newSerializeProxyStart(p.pkt.RawPacket, headroom)
			_, _ = serBuf.AppendBytes(quoteLen) // Implementation never fails.
			err = scmpP.SerializeTo(&serBuf, sopts)
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
			err = scmpH.SerializeTo(&serBuf, sopts)
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
		}
	} else {
		// We do not need to preserve the packet. Just pack our headers at the end of the buffer.
		// (this is what serializeProxy does by default).
		serBuf = newSerializeProxy(p.pkt.RawPacket)
		err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "serializing SCMP message")
		}
	}

	// serBuf now starts with the SCMP Headers and ends with the truncated quoted packet, if any.
	// This is what gets checksumed.
	if needsAuth {
		var e2e slayers.EndToEndExtn
		scionL.NextHdr = slayers.End2EndClass

		now := time.Now()
		dstA, err := scionL.DstAddr()
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "parsing destination address")
		}
		key, err := p.drkeyProvider.GetASHostKey(now, scionL.DstIA, dstA)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "retrieving DRKey")
		}
		if err := p.resetSPAOMetadata(key, now); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "resetting SPAO header")
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key.Key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        serBuf.Bytes(),
			},
			p.macInputBuffer,
			p.optAuth.Authenticator(),
		)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "computing CMAC")
		}
		if err := e2e.SerializeTo(&serBuf, sopts); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "serializing SCION E2E headers")
		}
	} else {
		scionL.NextHdr = slayers.L4SCMP
	}

	// Our SCION header is ready. Prepend it.
	if err := scionL.SerializeTo(&serBuf, sopts); err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "serializing SCION header")
	}

	// serBuf now has the exact slice that represents the packet.
	p.pkt.RawPacket = serBuf.Bytes()

	log.Debug("SCMP", "typecode", scmpH.TypeCode)
	return nil
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
	opts ...gopacket.DecodingLayer,
) (gopacket.DecodingLayer, error) {
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
