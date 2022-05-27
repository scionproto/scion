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

package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/addr"
	libepic "github.com/scionproto/scion/pkg/experimental/epic"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/slayers/path/epic"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/underlay/conn"
	underlayconn "github.com/scionproto/scion/private/underlay/conn"
	"github.com/scionproto/scion/router/bfd"
	"github.com/scionproto/scion/router/control"
)

const (
	// Number of packets to read in a single ReadBatch call.
	inputBatchCnt = 64

	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	bufSize = 9000

	// hopFieldDefaultExpTime is the default validity of the hop field
	// and 63 is equivalent to 6h.
	hopFieldDefaultExpTime = 63
)

type bfdSession interface {
	Run(ctx context.Context) error
	ReceiveMessage(*layers.BFD)
	IsUp() bool
}

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages) (int, error)
	WriteTo([]byte, *net.UDPAddr) (int, error)
	WriteBatch(msgs underlayconn.Messages, flags int) (int, error)
	Close() error
}

// DataPlane contains a SCION Border Router's forwarding logic. It reads packets
// from multiple sockets, performs routing, and sends them to their destinations
// (after updating the path, if that is needed).
//
// XXX(lukedirtwalker): this is still in development and not feature complete.
// Currently, only the following features are supported:
//  - initializing connections; MUST be done prior to calling Run
type DataPlane struct {
	external          map[uint16]BatchConn
	linkTypes         map[uint16]topology.LinkType
	neighborIAs       map[uint16]addr.IA
	internal          BatchConn
	internalIP        net.IP
	internalNextHops  map[uint16]*net.UDPAddr
	svc               *services
	macFactory        func() hash.Hash
	bfdSessions       map[uint16]bfdSession
	localIA           addr.IA
	mtx               sync.Mutex
	running           bool
	Metrics           *Metrics
	forwardingMetrics map[uint16]forwardingMetrics
}

var (
	alreadySet                    = serrors.New("already set")
	cannotRoute                   = serrors.New("cannot route, dropping pkt")
	emptyValue                    = serrors.New("empty value")
	malformedPath                 = serrors.New("malformed path content")
	modifyExisting                = serrors.New("modifying a running dataplane is not allowed")
	noSVCBackend                  = serrors.New("cannot find internal IP for the SVC")
	unsupportedPathType           = serrors.New("unsupported path type")
	unsupportedPathTypeNextHeader = serrors.New("unsupported combination")
	noBFDSessionFound             = serrors.New("no BFD sessions was found")
	noBFDSessionConfigured        = serrors.New("no BFD sessions have been configured")
	errBFDDisabled                = serrors.New("BFD is disabled")
)

type scmpError struct {
	TypeCode slayers.SCMPTypeCode
	Cause    error
}

func (e scmpError) Error() string {
	return serrors.New("scmp", "typecode", e.TypeCode, "cause", e.Cause).Error()
}

// SetIA sets the local IA for the dataplane.
func (d *DataPlane) SetIA(ia addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
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
	if d.running {
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

// AddInternalInterface sets the interface the data-plane will use to
// send/receive traffic in the local AS. This can only be called once; future
// calls will return an error. This can only be called on a not yet running
// dataplane.
func (d *DataPlane) AddInternalInterface(conn BatchConn, ip net.IP) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	if d.internal != nil {
		return alreadySet
	}
	d.internal = conn
	d.internalIP = ip
	return nil
}

// AddExternalInterface adds the inter AS connection for the given interface ID.
// If a connection for the given ID is already set this method will return an
// error. This can only be called on a not yet running dataplane.
func (d *DataPlane) AddExternalInterface(ifID uint16, conn BatchConn) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}
	if _, exists := d.external[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.external == nil {
		d.external = make(map[uint16]BatchConn)
	}
	d.external[ifID] = conn
	return nil
}

// AddNeighborIA adds the neighboring IA for a given interface ID. If an IA for
// the given ID is already set, this method will return an error. This can only
// be called on a yet running dataplane.
func (d *DataPlane) AddNeighborIA(ifID uint16, remote addr.IA) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
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

// AddExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *DataPlane) AddExternalInterfaceBFD(ifID uint16, conn BatchConn,
	src, dst control.LinkEnd, cfg control.BFD) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
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
	s := newBFDSend(conn, src.IA, dst.IA, src.Addr, dst.Addr, ifID, d.macFactory())
	return d.addBFDController(ifID, s, cfg, m)
}

// getInterfaceState checks if there is a bfd session for the input interfaceID and
// returns InterfaceUp if the relevant bfdsession state is up, or if there is no BFD
// session. Otherwise, it returns InterfaceDown.
func (d *DataPlane) getInterfaceState(interfaceID uint16) control.InterfaceState {
	bfdSessions := d.bfdSessions
	if bfdSession, ok := bfdSessions[interfaceID]; ok && !bfdSession.IsUp() {
		return control.InterfaceDown
	}
	return control.InterfaceUp
}

func (d *DataPlane) addBFDController(ifID uint16, s *bfdSend, cfg control.BFD,
	metrics bfd.Metrics) error {

	if cfg.Disable {
		return errBFDDisabled
	}
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
func (d *DataPlane) AddSvc(svc addr.HostSVC, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if a == nil {
		return emptyValue
	}
	if d.svc == nil {
		d.svc = newServices()
	}
	d.svc.AddSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceMetricLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(1)
	}
	return nil
}

// DelSvc deletes the address for the given service.
func (d *DataPlane) DelSvc(svc addr.HostSVC, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if a == nil {
		return emptyValue
	}
	if d.svc == nil {
		return nil
	}
	d.svc.DelSvc(svc, a)
	if d.Metrics != nil {
		labels := serviceMetricLabels(d.localIA, svc)
		d.Metrics.ServiceInstanceChanges.With(labels).Add(1)
		d.Metrics.ServiceInstanceCount.With(labels).Add(-1)
	}
	return nil
}

// AddNextHop sets the next hop address for the given interface ID. If the
// interface ID already has an address associated this operation fails. This can
// only be called on a not yet running dataplane.
func (d *DataPlane) AddNextHop(ifID uint16, a *net.UDPAddr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if a == nil {
		return emptyValue
	}
	if _, exists := d.internalNextHops[ifID]; exists {
		return serrors.WithCtx(alreadySet, "ifID", ifID)
	}
	if d.internalNextHops == nil {
		d.internalNextHops = make(map[uint16]*net.UDPAddr)
	}
	d.internalNextHops[ifID] = a
	return nil
}

// AddNextHopBFD adds the BFD session for the next hop address.
// If the remote ifID belongs to an existing address, the existing
// BFD session will be re-used.
func (d *DataPlane) AddNextHopBFD(ifID uint16, src, dst *net.UDPAddr, cfg control.BFD,
	sibling string) error {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}

	if dst == nil {
		return emptyValue
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

	s := newBFDSend(d.internal, d.localIA, d.localIA, src, dst, 0, d.macFactory())
	return d.addBFDController(ifID, s, cfg, m)
}

// Run starts running the dataplane. Note that configuration is not possible
// after calling this method.
func (d *DataPlane) Run(ctx context.Context) error {
	d.mtx.Lock()
	d.running = true

	d.initMetrics()

	read := func(ingressID uint16, rd BatchConn) {

		msgs := conn.NewReadMessages(inputBatchCnt)
		for _, msg := range msgs {
			msg.Buffers[0] = make([]byte, bufSize)
		}
		writeMsgs := make(underlayconn.Messages, 1)
		writeMsgs[0].Buffers = make([][]byte, 1)

		processor := newPacketProcessor(d, ingressID)
		var scmpErr scmpError
		for d.running {
			pkts, err := rd.ReadBatch(msgs)
			if err != nil {
				log.Debug("Failed to read batch", "err", err)
				// error metric
				continue
			}
			if pkts == 0 {
				continue
			}
			for _, p := range msgs[:pkts] {
				// input metric
				inputCounters := d.forwardingMetrics[ingressID]
				inputCounters.InputPacketsTotal.Inc()
				inputCounters.InputBytesTotal.Add(float64(p.N))

				srcAddr := p.Addr.(*net.UDPAddr)
				result, err := processor.processPkt(p.Buffers[0][:p.N], srcAddr)

				switch {
				case err == nil:
				case errors.As(err, &scmpErr):
					if !scmpErr.TypeCode.InfoMsg() {
						log.Debug("SCMP", "err", scmpErr, "dst_addr", p.Addr)
					}
					// SCMP go back the way they came.
					result.OutAddr = srcAddr
					result.OutConn = rd
				default:
					log.Debug("Error processing packet", "err", err)
					inputCounters.DroppedPacketsTotal.Inc()
					continue
				}
				if result.OutConn == nil { // e.g. BFD case no message is forwarded
					continue
				}

				// Write to OutConn; drop the packet if this would block.
				// Use WriteBatch because it's the only available function that
				// supports MSG_DONTWAIT.
				writeMsgs[0].Buffers[0] = result.OutPkt
				writeMsgs[0].Addr = nil
				if result.OutAddr != nil { // don't assign directly to net.Addr, typed nil!
					writeMsgs[0].Addr = result.OutAddr
				}

				_, err = result.OutConn.WriteBatch(writeMsgs, syscall.MSG_DONTWAIT)
				if err != nil {
					var errno syscall.Errno
					if !errors.As(err, &errno) ||
						!(errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK) {
						log.Debug("Error writing packet", "err", err)
						// error metric
					}
					inputCounters.DroppedPacketsTotal.Inc()
					continue
				}
				// ok metric
				outputCounters := d.forwardingMetrics[result.EgressID]
				outputCounters.OutputPacketsTotal.Inc()
				outputCounters.OutputBytesTotal.Add(float64(len(result.OutPkt)))
			}
		}
	}

	for k, v := range d.bfdSessions {
		go func(ifID uint16, c bfdSession) {
			defer log.HandlePanic()
			if err := c.Run(ctx); err != nil && err != bfd.AlreadyRunning {
				log.Error("BFD session failed to start", "ifID", ifID, "err", err)
			}
		}(k, v)
	}
	for ifID, v := range d.external {
		go func(i uint16, c BatchConn) {
			defer log.HandlePanic()
			read(i, c)
		}(ifID, v)
	}
	go func(c BatchConn) {
		defer log.HandlePanic()
		read(0, c)
	}(d.internal)

	d.mtx.Unlock()

	<-ctx.Done()
	return nil
}

// initMetrics initializes the metrics related to packet forwarding. The
// counters are already instantiated for all the relevant interfaces so this
// will not have to be repeated during packet forwarding.
func (d *DataPlane) initMetrics() {
	d.forwardingMetrics = make(map[uint16]forwardingMetrics)
	labels := interfaceToMetricLabels(0, d.localIA, d.neighborIAs)
	d.forwardingMetrics[0] = initForwardingMetrics(d.Metrics, labels)
	for id := range d.external {
		if _, notOwned := d.internalNextHops[id]; notOwned {
			continue
		}
		labels = interfaceToMetricLabels(id, d.localIA, d.neighborIAs)
		d.forwardingMetrics[id] = initForwardingMetrics(d.Metrics, labels)
	}
}

type processResult struct {
	EgressID uint16
	OutConn  BatchConn
	OutAddr  *net.UDPAddr
	OutPkt   []byte
}

func newPacketProcessor(d *DataPlane, ingressID uint16) *scionPacketProcessor {
	p := &scionPacketProcessor{
		d:         d,
		ingressID: ingressID,
		buffer:    gopacket.NewSerializeBuffer(),
		mac:       d.macFactory(),
		macBuffers: macBuffers{
			scionInput: make([]byte, path.MACBufferSize),
			epicInput:  make([]byte, libepic.MACBufferSize),
		},
	}
	p.scionLayer.RecyclePaths()
	return p
}

func (p *scionPacketProcessor) reset() error {
	p.rawPkt = nil
	//p.scionLayer // cannot easily be reset
	p.path = nil
	p.hopField = path.HopField{}
	p.infoField = path.InfoField{}
	p.segmentChange = false
	if err := p.buffer.Clear(); err != nil {
		return serrors.WrapStr("Failed to clear buffer", err)
	}
	p.mac.Reset()
	p.cachedMac = nil
	return nil
}

func (p *scionPacketProcessor) processPkt(rawPkt []byte,
	srcAddr *net.UDPAddr) (processResult, error) {

	p.reset()
	p.rawPkt = rawPkt

	// parse SCION header and skip extensions;
	var err error
	p.lastLayer, err = decodeLayers(p.rawPkt, &p.scionLayer, &p.hbhLayer, &p.e2eLayer)
	if err != nil {
		return processResult{}, err
	}
	pld := p.lastLayer.LayerPayload()

	pathType := p.scionLayer.PathType
	switch pathType {
	case empty.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			return processResult{}, p.processIntraBFD(srcAddr, pld)
		}
		return processResult{}, serrors.WithCtx(unsupportedPathTypeNextHeader,
			"type", pathType, "header", nextHdr(p.lastLayer))
	case onehop.PathType:
		if p.lastLayer.NextLayerType() == layers.LayerTypeBFD {
			ohp, ok := p.scionLayer.Path.(*onehop.Path)
			if !ok {
				return processResult{}, malformedPath
			}
			return processResult{}, p.processInterBFD(ohp, pld)
		}
		return p.processOHP()
	case scion.PathType:
		return p.processSCION()
	case epic.PathType:
		return p.processEPIC()
	default:
		return processResult{}, serrors.WithCtx(unsupportedPathType, "type", pathType)
	}
}

func (p *scionPacketProcessor) processInterBFD(oh *onehop.Path, data []byte) error {
	if len(p.d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	if v, ok := p.d.bfdSessions[p.ingressID]; ok {
		v.ReceiveMessage(bfd)
		return nil
	}

	return noBFDSessionFound
}

func (p *scionPacketProcessor) processIntraBFD(src *net.UDPAddr, data []byte) error {
	if len(p.d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}

	bfd := &p.bfdLayer
	if err := bfd.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	ifID := uint16(0)
	for k, v := range p.d.internalNextHops {
		if bytes.Equal(v.IP, src.IP) && v.Port == src.Port {
			ifID = k
			break
		}
	}

	if v, ok := p.d.bfdSessions[ifID]; ok {
		v.ReceiveMessage(bfd)
		return nil
	}

	return noBFDSessionFound
}

func (p *scionPacketProcessor) processSCION() (processResult, error) {

	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, malformedPath
	}
	return p.process()
}

func (p *scionPacketProcessor) processEPIC() (processResult, error) {

	epicPath, ok := p.scionLayer.Path.(*epic.Path)
	if !ok {
		return processResult{}, malformedPath
	}

	p.path = epicPath.ScionPath
	if p.path == nil {
		return processResult{}, malformedPath
	}

	isPenultimate := p.path.IsPenultimateHop()
	isLast := p.path.IsLastHop()

	result, err := p.process()
	if err != nil {
		return result, err
	}

	if isPenultimate || isLast {
		firstInfo, err := p.path.GetInfoField(0)
		if err != nil {
			return processResult{}, err
		}

		timestamp := time.Unix(int64(firstInfo.Timestamp), 0)
		err = libepic.VerifyTimestamp(timestamp, epicPath.PktID.Timestamp, time.Now())
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}

		HVF := epicPath.PHVF
		if isLast {
			HVF = epicPath.LHVF
		}
		err = libepic.VerifyHVF(p.cachedMac, epicPath.PktID,
			&p.scionLayer, firstInfo.Timestamp, HVF, p.macBuffers.epicInput)
		if err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}
	}

	return result, nil
}

// scionPacketProcessor processes packets. It contains pre-allocated per-packet
// mutable state and context information which should be reused.
type scionPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// ingressID is the interface ID this packet came in, determined from the
	// socket.
	ingressID uint16
	// rawPkt is the raw packet, it is updated during processing to contain the
	// message to send out.
	rawPkt []byte
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
	// segmentChange indicates if the path segment was changed during processing.
	segmentChange bool

	// cachedMac contains the full 16 bytes of the MAC. Will be set during processing.
	// For a hop performing an Xover, it is the MAC corresponding to the down segment.
	cachedMac []byte
	// macBuffers avoid allocating memory during processing.
	macBuffers macBuffers

	// bfdLayer is reusable buffer for parsing BFD messages
	bfdLayer layers.BFD
}

// macBuffers are preallocated buffers for the in- and outputs of MAC functions.
type macBuffers struct {
	scionInput []byte
	epicInput  []byte
}

func (p *scionPacketProcessor) packSCMP(scmpH *slayers.SCMP, scmpP gopacket.SerializableLayer,
	cause error) (processResult, error) {

	// check invoking packet was an SCMP error:
	if p.lastLayer.NextLayerType() == slayers.LayerTypeSCMP {
		var scmpLayer slayers.SCMP
		err := scmpLayer.DecodeFromBytes(p.lastLayer.LayerPayload(), gopacket.NilDecodeFeedback)
		if err != nil {
			return processResult{}, serrors.WrapStr("decoding SCMP layer", err)
		}
		if !scmpLayer.TypeCode.InfoMsg() {
			return processResult{}, serrors.WrapStr("SCMP error for SCMP error pkt -> DROP", cause)
		}
	}

	rawSCMP, err := p.prepareSCMP(
		scmpH,
		scmpP,
		cause,
	)
	return processResult{OutPkt: rawSCMP}, err
}

func (p *scionPacketProcessor) parsePath() (processResult, error) {
	var err error
	p.hopField, err = p.path.GetCurrentHopField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, err
	}
	p.infoField, err = p.path.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, err
	}
	if r, err := p.validateHopExpiry(); err != nil {
		return r, err
	}
	if r, err := p.validateIngressID(); err != nil {
		return r, err
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateHopExpiry() (processResult, error) {
	expiration := util.SecsToTime(p.infoField.Timestamp).
		Add(path.ExpTimeToDuration(p.hopField.ExpTime))
	expired := expiration.Before(time.Now())
	if !expired {
		return processResult{}, nil
	}
	return p.packSCMP(
		&slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
			slayers.SCMPCodePathExpired),
		},
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		serrors.New("expired hop", "cons_dir", p.infoField.ConsDir, "if_id", p.ingressID,
			"curr_inf", p.path.PathMeta.CurrINF, "curr_hf", p.path.PathMeta.CurrHF),
	)
}

func (p *scionPacketProcessor) validateIngressID() (processResult, error) {
	pktIngressID := p.hopField.ConsIngress
	errCode := slayers.SCMPCodeUnknownHopFieldIngress
	if !p.infoField.ConsDir {
		pktIngressID = p.hopField.ConsEgress
		errCode = slayers.SCMPCodeUnknownHopFieldEgress
	}
	if p.ingressID != 0 && p.ingressID != pktIngressID {
		return p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, errCode),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("ingress interface invalid",
				"pkt_ingress", pktIngressID, "router_ingress", p.ingressID),
		)
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) validateEgressID() (processResult, error) {
	pktEgressID := p.egressInterface()
	_, ih := p.d.internalNextHops[pktEgressID]
	_, eh := p.d.external[pktEgressID]
	if !ih && !eh {
		errCode := slayers.SCMPCodeUnknownHopFieldEgress
		if !p.infoField.ConsDir {
			errCode = slayers.SCMPCodeUnknownHopFieldIngress
		}
		return p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, errCode),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			cannotRoute,
		)
	}

	if !p.segmentChange {
		return processResult{}, nil
	}
	// Check that the interface pair is valid on a segment switch.
	// Having a segment change received from the internal interface is never valid.
	ingress, egress := p.d.linkTypes[p.ingressID], p.d.linkTypes[pktEgressID]
	switch {
	case ingress == topology.Core && egress == topology.Child:
		return processResult{}, nil
	case ingress == topology.Child && egress == topology.Core:
		return processResult{}, nil
	case ingress == topology.Child && egress == topology.Child:
		return processResult{}, nil
	default:
		return p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(
					slayers.SCMPTypeParameterProblem,
					slayers.SCMPCodeInvalidSegmentChange,
				),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentInfoPointer()},
			serrors.WithCtx(cannotRoute, "ingress_id", p.ingressID, "ingress_type", ingress,
				"egress_id", pktEgressID, "egress_type", egress))
	}
}

func (p *scionPacketProcessor) updateNonConsDirIngressSegID() error {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// TODO(lukedirtwalker): For packets destined to peer links this shouldn't
	// be updated.
	if !p.infoField.ConsDir && p.ingressID != 0 {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			return serrors.WrapStr("update info field", err)
		}
	}
	return nil
}

func (p *scionPacketProcessor) currentInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*int(p.path.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*p.path.NumINF + path.HopLen*int(p.path.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentMAC() (processResult, error) {
	fullMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macBuffers.scionInput)
	if subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], fullMac[:path.MacLen]) == 0 {
		return p.packSCMP(
			&slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeInvalidHopFieldMAC),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("MAC verification failed", "expected", fmt.Sprintf(
				"%x", fullMac[:path.MacLen]),
				"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
				"cons_dir", p.infoField.ConsDir,
				"if_id", p.ingressID, "curr_inf", p.path.PathMeta.CurrINF,
				"curr_hf", p.path.PathMeta.CurrHF, "seg_id", p.infoField.SegID),
		)
	}
	// Add the full MAC to the SCION packet processor,
	// such that EPIC does not need to recalculate it.
	p.cachedMac = fullMac

	return processResult{}, nil
}

func (p *scionPacketProcessor) resolveInbound() (*net.UDPAddr, processResult, error) {
	a, err := p.d.resolveLocalDst(p.scionLayer)
	switch {
	case errors.Is(err, noSVCBackend):
		r, err := p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable,
					slayers.SCMPCodeNoRoute),
			},
			&slayers.SCMPDestinationUnreachable{}, err)
		return nil, r, err
	default:
		return a, processResult{}, nil
	}
}

func (p *scionPacketProcessor) processEgress() error {
	// we are the egress router and if we go in construction direction we
	// need to update the SegID.
	if p.infoField.ConsDir {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return serrors.WrapStr("update info field", err)
		}
	}
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return serrors.WrapStr("incrementing path", err)
	}
	return nil
}

func (p *scionPacketProcessor) doXover() (processResult, error) {
	p.segmentChange = true
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, serrors.WrapStr("incrementing path", err)
	}
	var err error
	if p.hopField, err = p.path.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	if p.infoField, err = p.path.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return processResult{}, err
	}
	if r, err := p.validateHopExpiry(); err != nil {
		return r, err
	}
	// verify the new block
	if r, err := p.verifyCurrentMAC(); err != nil {
		return r, serrors.WithCtx(err, "info", "after xover")
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) egressInterface() uint16 {
	if p.infoField.ConsDir {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

func (p *scionPacketProcessor) validateEgressUp() (processResult, error) {
	egressID := p.egressInterface()
	if v, ok := p.d.bfdSessions[egressID]; ok {
		if !v.IsUp() {
			scmpH := &slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeExternalInterfaceDown, 0),
			}
			var scmpP gopacket.SerializableLayer = &slayers.SCMPExternalInterfaceDown{
				IA:   p.d.localIA,
				IfID: uint64(egressID),
			}
			if _, external := p.d.external[egressID]; !external {
				scmpH.TypeCode =
					slayers.CreateSCMPTypeCode(slayers.SCMPTypeInternalConnectivityDown, 0)
				scmpP = &slayers.SCMPInternalConnectivityDown{
					IA:      p.d.localIA,
					Ingress: uint64(p.ingressID),
					Egress:  uint64(egressID),
				}
			}
			return p.packSCMP(scmpH, scmpP, serrors.New("bfd session down"))
		}
	}
	return processResult{}, nil
}

func (p *scionPacketProcessor) handleIngressRouterAlert() (processResult, error) {
	if p.ingressID == 0 {
		return processResult{}, nil
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(p.ingressID)
}

func (p *scionPacketProcessor) ingressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.EgressRouterAlert
	}
	return &p.hopField.IngressRouterAlert
}

func (p *scionPacketProcessor) handleEgressRouterAlert() (processResult, error) {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return processResult{}, nil
	}
	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; !ok {
		return processResult{}, nil
	}
	*alert = false
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	return p.handleSCMPTraceRouteRequest(egressID)
}

func (p *scionPacketProcessor) egressRouterAlertFlag() *bool {
	if !p.infoField.ConsDir {
		return &p.hopField.IngressRouterAlert
	}
	return &p.hopField.EgressRouterAlert
}

func (p *scionPacketProcessor) handleSCMPTraceRouteRequest(
	interfaceID uint16) (processResult, error) {

	if p.lastLayer.NextLayerType() != slayers.LayerTypeSCMP {
		log.Debug("Packet with router alert, but not SCMP")
		return processResult{}, nil
	}
	scionPld := p.lastLayer.LayerPayload()
	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(scionPld, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMP header of router alert", "err", err)
		return processResult{}, nil
	}
	if scmpH.TypeCode != slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0) {
		log.Debug("Packet with router alert, but not traceroute request",
			"type_code", scmpH.TypeCode)
		return processResult{}, nil
	}
	var scmpP slayers.SCMPTraceroute
	if err := scmpP.DecodeFromBytes(scmpH.Payload, gopacket.NilDecodeFeedback); err != nil {
		log.Debug("Parsing SCMPTraceroute", "err", err)
		return processResult{}, nil
	}
	scmpH = slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpP = slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         p.d.localIA,
		Interface:  uint64(interfaceID),
	}
	return p.packSCMP(&scmpH, &scmpP, nil)
}

func (p *scionPacketProcessor) validatePktLen() (processResult, error) {
	if int(p.scionLayer.PayloadLen) == len(p.scionLayer.Payload) {
		return processResult{}, nil
	}
	return p.packSCMP(
		&slayers.SCMP{
			TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeInvalidPacketSize),
		},
		&slayers.SCMPParameterProblem{Pointer: 0},
		serrors.New("bad packet size",
			"header", p.scionLayer.PayloadLen, "actual", len(p.scionLayer.Payload)),
	)
}

func (p *scionPacketProcessor) process() (processResult, error) {

	if r, err := p.parsePath(); err != nil {
		return r, err
	}
	if r, err := p.validatePktLen(); err != nil {
		return r, err
	}
	if err := p.updateNonConsDirIngressSegID(); err != nil {
		return processResult{}, err
	}
	if r, err := p.verifyCurrentMAC(); err != nil {
		return r, err
	}
	if r, err := p.handleIngressRouterAlert(); err != nil {
		return r, err
	}

	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA.Equal(p.d.localIA) && int(p.path.PathMeta.CurrHF)+1 == p.path.NumHops {
		a, r, err := p.resolveInbound()
		if err != nil {
			return r, err
		}
		return processResult{OutConn: p.d.internal, OutAddr: a, OutPkt: p.rawPkt}, nil
	}

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.

	if p.path.IsXover() {
		if r, err := p.doXover(); err != nil {
			return r, err
		}
	}
	if r, err := p.validateEgressID(); err != nil {
		return r, err
	}
	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if r, err := p.handleEgressRouterAlert(); err != nil {
		return r, err
	}
	if r, err := p.validateEgressUp(); err != nil {
		return r, err
	}

	egressID := p.egressInterface()
	if c, ok := p.d.external[egressID]; ok {
		if err := p.processEgress(); err != nil {
			return processResult{}, err
		}
		return processResult{EgressID: egressID, OutConn: c, OutPkt: p.rawPkt}, nil
	}

	// ASTransit: pkts leaving from another AS BR.
	if a, ok := p.d.internalNextHops[egressID]; ok {
		return processResult{OutConn: p.d.internal, OutAddr: a, OutPkt: p.rawPkt}, nil
	}
	errCode := slayers.SCMPCodeUnknownHopFieldEgress
	if !p.infoField.ConsDir {
		errCode = slayers.SCMPCodeUnknownHopFieldIngress
	}
	return p.packSCMP(
		&slayers.SCMP{
			TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, errCode),
		},
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		cannotRoute,
	)
}

func (p *scionPacketProcessor) processOHP() (processResult, error) {
	s := p.scionLayer
	ohp, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return processResult{}, malformedPath
	}
	if !ohp.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return processResult{}, serrors.WrapStr(
			"OneHop path in reverse construction direction is not allowed",
			malformedPath, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}

	// OHP leaving our IA
	if p.ingressID == 0 {
		if !p.d.localIA.Equal(s.SrcIA) {
			// TODO parameter problem -> invalid path
			return processResult{}, serrors.WrapStr("bad source IA", cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress,
				"localIA", p.d.localIA, "srcIA", s.SrcIA)
		}
		neighborIA, ok := p.d.neighborIAs[ohp.FirstHop.ConsEgress]
		if !ok {
			// TODO parameter problem invalid interface
			return processResult{}, serrors.WithCtx(cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress)
		}
		if !neighborIA.Equal(s.DstIA) {
			return processResult{}, serrors.WrapStr("bad destination IA", cannotRoute,
				"type", "ohp", "egress", ohp.FirstHop.ConsEgress,
				"neighborIA", neighborIA, "dstIA", s.DstIA)
		}
		mac := path.MAC(p.mac, ohp.Info, ohp.FirstHop, p.macBuffers.scionInput)
		if subtle.ConstantTimeCompare(ohp.FirstHop.Mac[:], mac[:]) == 0 {
			// TODO parameter problem -> invalid MAC
			return processResult{}, serrors.New("MAC", "expected", fmt.Sprintf("%x", mac),
				"actual", fmt.Sprintf("%x", ohp.FirstHop.Mac), "type", "ohp")
		}
		ohp.Info.UpdateSegID(ohp.FirstHop.Mac)

		if err := updateSCIONLayer(p.rawPkt, s, p.buffer); err != nil {
			return processResult{}, err
		}
		// OHP should always be directed to the correct BR.
		if c, ok := p.d.external[ohp.FirstHop.ConsEgress]; ok {
			// buffer should already be correct
			return processResult{EgressID: ohp.FirstHop.ConsEgress, OutConn: c, OutPkt: p.rawPkt},
				nil
		}
		// TODO parameter problem invalid interface
		return processResult{}, serrors.WithCtx(cannotRoute, "type", "ohp",
			"egress", ohp.FirstHop.ConsEgress, "consDir", ohp.Info.ConsDir)
	}

	// OHP entering our IA
	if !p.d.localIA.Equal(s.DstIA) {
		return processResult{}, serrors.WrapStr("bad destination IA", cannotRoute,
			"type", "ohp", "ingress", p.ingressID,
			"localIA", p.d.localIA, "dstIA", s.DstIA)
	}
	neighborIA := p.d.neighborIAs[p.ingressID]
	if !neighborIA.Equal(s.SrcIA) {
		return processResult{}, serrors.WrapStr("bad source IA", cannotRoute,
			"type", "ohp", "ingress", p.ingressID,
			"neighborIA", neighborIA, "srcIA", s.SrcIA)
	}

	ohp.SecondHop = path.HopField{
		ConsIngress: p.ingressID,
		ExpTime:     ohp.FirstHop.ExpTime,
	}
	// XXX(roosd): Here we leak the buffer into the SCION packet header.
	// This is okay because we do not operate on the buffer or the packet
	// for the rest of processing.
	ohp.SecondHop.Mac = path.MAC(p.mac, ohp.Info, ohp.SecondHop, p.macBuffers.scionInput)

	if err := updateSCIONLayer(p.rawPkt, s, p.buffer); err != nil {
		return processResult{}, err
	}
	a, err := p.d.resolveLocalDst(s)
	if err != nil {
		return processResult{}, err
	}
	return processResult{OutConn: p.d.internal, OutAddr: a, OutPkt: p.rawPkt}, nil
}

func (d *DataPlane) resolveLocalDst(s slayers.SCION) (*net.UDPAddr, error) {
	dst, err := s.DstAddr()
	if err != nil {
		// TODO parameter problem.
		return nil, err
	}
	switch v := dst.(type) {
	case addr.HostSVC:
		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		a, ok := d.svc.Any(v.Base())
		if !ok {
			return nil, noSVCBackend
		}
		return a, nil
	case *net.IPAddr:
		return addEndhostPort(v), nil
	default:
		panic("unexpected address type returned from DstAddr")
	}
}

func addEndhostPort(dst *net.IPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: dst.IP, Port: topology.EndhostPort}
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
	srcAddr, dstAddr *net.UDPAddr
	scn              *slayers.SCION
	ohp              *onehop.Path
	mac              hash.Hash
	macBuffer        []byte
	buffer           gopacket.SerializeBuffer
}

// newBFDSend creates and initializes a BFD Sender
func newBFDSend(conn BatchConn, srcIA, dstIA addr.IA, srcAddr, dstAddr *net.UDPAddr,
	ifID uint16, mac hash.Hash) *bfdSend {

	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      slayers.L4BFD,
		SrcIA:        srcIA,
		DstIA:        dstIA,
	}

	if err := scn.SetSrcAddr(&net.IPAddr{IP: srcAddr.IP}); err != nil {
		panic(err) // Must work unless IPAddr is not supported
	}
	if err := scn.SetDstAddr(&net.IPAddr{IP: dstAddr.IP}); err != nil {
		panic(err) // Must work unless IPAddr is not supported
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
	}
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

func (p *scionPacketProcessor) prepareSCMP(scmpH *slayers.SCMP, scmpP gopacket.SerializableLayer,
	cause error) ([]byte, error) {

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

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() {
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	_, external := p.d.external[p.ingressID]
	if external {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir {
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
	srcA, err := p.scionLayer.SrcAddr()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "extracting src addr")
	}
	if err := scionL.SetDstAddr(srcA); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting dest addr")
	}
	if err := scionL.SetSrcAddr(&net.IPAddr{IP: p.d.internalIP}); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting src addr")
	}
	scionL.NextHdr = slayers.L4SCMP

	scmpH.SetNetworkLayerForChecksum(&scionL)

	if err := p.buffer.Clear(); err != nil {
		return nil, err
	}

	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	scmpLayers := []gopacket.SerializableLayer{&scionL, scmpH, scmpP}
	if cause != nil {
		// add quote for errors.
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len()
		switch scmpH.TypeCode.Type() {
		case slayers.SCMPTypeExternalInterfaceDown:
			hdrLen += 20
		case slayers.SCMPTypeInternalConnectivityDown:
			hdrLen += 28
		default:
			hdrLen += 8
		}
		quote := p.rawPkt
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if len(quote) > maxQuoteLen {
			quote = quote[:maxQuoteLen]
		}
		scmpLayers = append(scmpLayers, gopacket.Payload(quote))
	}
	// XXX(matzf) could we use iovec gather to avoid copying quote?
	err = gopacket.SerializeLayers(p.buffer, sopts, scmpLayers...)
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCMP message")
	}
	return p.buffer.Bytes(), scmpError{TypeCode: scmpH.TypeCode, Cause: cause}
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
	case *slayers.EndToEndExtn:
		return v.NextHdr
	case *slayers.HopByHopExtn:
		return v.NextHdr
	default:
		return slayers.L4None
	}
}

// forwardingMetrics contains the subset of Metrics relevant for forwarding,
// instantiated with some interface-specific labels.
type forwardingMetrics struct {
	InputBytesTotal     prometheus.Counter
	OutputBytesTotal    prometheus.Counter
	InputPacketsTotal   prometheus.Counter
	OutputPacketsTotal  prometheus.Counter
	DroppedPacketsTotal prometheus.Counter
}

func initForwardingMetrics(metrics *Metrics, labels prometheus.Labels) forwardingMetrics {
	c := forwardingMetrics{
		InputBytesTotal:     metrics.InputBytesTotal.With(labels),
		InputPacketsTotal:   metrics.InputPacketsTotal.With(labels),
		OutputBytesTotal:    metrics.OutputBytesTotal.With(labels),
		OutputPacketsTotal:  metrics.OutputPacketsTotal.With(labels),
		DroppedPacketsTotal: metrics.DroppedPacketsTotal.With(labels),
	}
	c.InputBytesTotal.Add(0)
	c.InputPacketsTotal.Add(0)
	c.OutputBytesTotal.Add(0)
	c.OutputPacketsTotal.Add(0)
	c.DroppedPacketsTotal.Add(0)
	return c
}

func interfaceToMetricLabels(id uint16, localIA addr.IA,
	neighbors map[uint16]addr.IA) prometheus.Labels {

	if id == 0 {
		return prometheus.Labels{
			"isd_as":          localIA.String(),
			"interface":       "internal",
			"neighbor_isd_as": localIA.String(),
		}
	}
	return prometheus.Labels{
		"isd_as":          localIA.String(),
		"interface":       strconv.FormatUint(uint64(id), 10),
		"neighbor_isd_as": neighbors[id].String(),
	}
}

func serviceMetricLabels(localIA addr.IA, svc addr.HostSVC) prometheus.Labels {
	return prometheus.Labels{
		"isd_as":  localIA.String(),
		"service": svc.BaseString(),
	}
}
