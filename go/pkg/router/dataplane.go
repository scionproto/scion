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
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	libepic "github.com/scionproto/scion/go/lib/epic"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/empty"
	"github.com/scionproto/scion/go/lib/slayers/path/epic"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	underlayconn "github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/router/bfd"
	"github.com/scionproto/scion/go/pkg/router/control"
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
	Run() error
	Messages() chan<- *layers.BFD
	IsUp() bool
}

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages) (int, error)
	WriteBatch(underlayconn.Messages) (int, error)
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
	internalNextHops  map[uint16]net.Addr
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
		labels := []string{
			"interface", fmt.Sprint(ifID),
			"isd_as", d.localIA.String(),
			"neighbor_isd_as", dst.IA.String(),
		}
		m = bfd.Metrics{
			Up: metrics.NewPromGauge(d.Metrics.InterfaceUp).
				With(labels...),
			StateChanges: metrics.NewPromCounter(d.Metrics.BFDInterfaceStateChanges).
				With(labels...),
			PacketsSent: metrics.NewPromCounter(d.Metrics.BFDPacketsSent).
				With(labels...),
			PacketsReceived: metrics.NewPromCounter(d.Metrics.BFDPacketsReceived).
				With(labels...),
		}
	}
	s := &bfdSend{
		conn:       conn,
		srcAddr:    src.Addr,
		dstAddr:    dst.Addr,
		srcIA:      src.IA,
		dstIA:      dst.IA,
		ifID:       ifID,
		macFactory: d.macFactory,
	}
	return d.addBFDController(ifID, s, cfg, m)
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
		Logger:                log.New("component", "BFD"),
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
func (d *DataPlane) AddNextHop(ifID uint16, a net.Addr) error {
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
		d.internalNextHops = make(map[uint16]net.Addr)
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
		labels := []string{"isd_as", d.localIA.String(), "sibling", sibling}
		m = bfd.Metrics{
			Up: metrics.NewPromGauge(d.Metrics.SiblingReachable).
				With(labels...),
			StateChanges: metrics.NewPromCounter(d.Metrics.SiblingBFDStateChanges).
				With(labels...),
			PacketsSent: metrics.NewPromCounter(d.Metrics.SiblingBFDPacketsSent).
				With(labels...),
			PacketsReceived: metrics.NewPromCounter(d.Metrics.SiblingBFDPacketsReceived).
				With(labels...),
		}
	}
	s := &bfdSend{
		conn:       d.internal,
		srcAddr:    src,
		dstAddr:    dst,
		srcIA:      d.localIA,
		dstIA:      d.localIA,
		ifID:       0,
		macFactory: d.macFactory,
	}
	return d.addBFDController(ifID, s, cfg, m)
}

// Run starts running the dataplane. Note that configuration is not possible
// after calling this method.
func (d *DataPlane) Run() error {
	d.mtx.Lock()
	d.running = true

	d.initMetrics()

	read := func(ingressID uint16, rd BatchConn) {

		msgs := conn.NewReadMessages(inputBatchCnt)
		for _, msg := range msgs {
			msg.Buffers[0] = make([]byte, bufSize)
		}

		var scmpErr scmpError
		spkt := slayers.SCION{}
		buffer := gopacket.NewSerializeBuffer()
		origPacket := make([]byte, bufSize)
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
				origPacket = origPacket[:p.N]
				// TODO(karampok). Use meta for sanity checks.
				p.Buffers[0] = p.Buffers[0][:p.N]
				copy(origPacket[:p.N], p.Buffers[0])

				// input metric
				inputCounters := d.forwardingMetrics[ingressID]
				inputCounters.InputPacketsTotal.Inc()
				inputCounters.InputBytesTotal.Add(float64(p.N))

				result, err := d.processPkt(ingressID, p.Buffers[0], p.Addr, spkt, origPacket,
					buffer)

				switch {
				case err == nil:
				case errors.As(err, &scmpErr):
					if !scmpErr.TypeCode.InfoMsg() {
						log.Debug("SCMP", "err", scmpErr, "dst_addr", p.Addr)
					}
					// SCMP go back the way they came.
					result.OutAddr = p.Addr
					result.OutConn = rd
				default:
					log.Debug("Error processing packet", "err", err)
					inputCounters.DroppedPacketsTotal.Inc()
					continue
				}
				if result.OutConn == nil { // e.g. BFD case no message is forwarded
					continue
				}
				_, err = result.OutConn.WriteBatch(underlayconn.Messages([]ipv4.Message{{
					Buffers: [][]byte{result.OutPkt},
					Addr:    result.OutAddr,
				}}))
				if err != nil {
					log.Debug("Error writing packet", "err", err)
					// error metric
					continue
				}
				// ok metric
				outputCounters := d.forwardingMetrics[result.EgressID]
				outputCounters.OutputPacketsTotal.Inc()
				outputCounters.OutputBytesTotal.Add(float64(len(result.OutPkt)))
			}

			// Reset buffers to original capacity.
			for _, p := range msgs[:pkts] {
				p.Buffers[0] = p.Buffers[0][:bufSize]
			}
		}
	}

	for k, v := range d.bfdSessions {
		go func(ifID uint16, c bfdSession) {
			defer log.HandlePanic()
			if err := c.Run(); err != nil && err != bfd.AlreadyRunning {
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

	select {}
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
	OutAddr  net.Addr
	OutPkt   []byte
}

func (d *DataPlane) processPkt(ingressID uint16, rawPkt []byte, srcAddr net.Addr, s slayers.SCION,
	origPacket []byte, buffer gopacket.SerializeBuffer) (processResult, error) {

	if err := s.DecodeFromBytes(rawPkt, gopacket.NilDecodeFeedback); err != nil {
		return processResult{}, err
	}
	if err := buffer.Clear(); err != nil {
		return processResult{}, serrors.WrapStr("Failed to clear buffer", err)
	}

	switch s.PathType {
	case empty.PathType:
		if s.NextHdr == common.L4BFD {
			return processResult{}, d.processIntraBFD(srcAddr, s.Payload)
		}
		return processResult{}, serrors.WithCtx(unsupportedPathTypeNextHeader,
			"type", s.PathType, "header", s.NextHdr)
	case onehop.PathType:
		if s.NextHdr == common.L4BFD {
			ohp, ok := s.Path.(*onehop.Path)
			if !ok {
				return processResult{}, malformedPath
			}
			return processResult{}, d.processInterBFD(ingressID, ohp, s.Payload)
		}
		return d.processOHP(ingressID, rawPkt, s, buffer)
	case scion.PathType:
		return d.processSCION(ingressID, rawPkt, s, origPacket, buffer)
	case epic.PathType:
		return d.processEPIC(ingressID, rawPkt, s, origPacket, buffer)
	default:
		return processResult{}, serrors.WithCtx(unsupportedPathType, "type", s.PathType)
	}
}

func (d *DataPlane) processInterBFD(ingressID uint16, oh *onehop.Path, data []byte) error {
	if len(d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}

	p := &layers.BFD{}
	if err := p.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	if v, ok := d.bfdSessions[ingressID]; ok {
		v.Messages() <- p
		return nil
	}

	return noBFDSessionFound
}

func (d *DataPlane) processIntraBFD(src net.Addr, data []byte) error {
	if len(d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}
	p := &layers.BFD{}
	if err := p.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}

	ifID := uint16(0)
	srcUDPAddr, ok := src.(*net.UDPAddr)
	if !ok {
		return serrors.New("type assertion failure", "from", fmt.Sprintf("%v(%T)", src, src),
			"expected", "*net.IPAddr")
	}

	for k, v := range d.internalNextHops {
		remoteUDPAddr, ok := v.(*net.UDPAddr)
		if !ok {
			return serrors.New("type assertion failure", "from",
				fmt.Sprintf("%v(%T)", remoteUDPAddr, remoteUDPAddr), "expected", "*net.UDPAddr")
		}
		if bytes.Equal(remoteUDPAddr.IP, srcUDPAddr.IP) && remoteUDPAddr.Port == srcUDPAddr.Port {
			ifID = k
			continue
		}
	}

	if v, ok := d.bfdSessions[ifID]; ok {
		v.Messages() <- p
		return nil
	}

	return noBFDSessionFound
}

func (d *DataPlane) processSCION(ingressID uint16, rawPkt []byte, s slayers.SCION,
	origPacket []byte, buffer gopacket.SerializeBuffer) (processResult, error) {

	p := scionPacketProcessor{
		d:          d,
		ingressID:  ingressID,
		rawPkt:     rawPkt,
		scionLayer: s,
		origPacket: origPacket,
		buffer:     buffer,
	}

	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return processResult{}, malformedPath
	}

	return p.process()
}

func (d *DataPlane) processEPIC(ingressID uint16, rawPkt []byte, s slayers.SCION,
	origPacket []byte, buffer gopacket.SerializeBuffer) (processResult, error) {

	path, ok := s.Path.(*epic.Path)
	if !ok {
		return processResult{}, malformedPath
	}

	scionPath := path.ScionPath
	if scionPath == nil {
		return processResult{}, malformedPath
	}

	info, err := scionPath.GetCurrentInfoField()
	if err != nil {
		return processResult{}, err
	}

	p := scionPacketProcessor{
		d:          d,
		ingressID:  ingressID,
		rawPkt:     rawPkt,
		scionLayer: s,
		origPacket: origPacket,
		buffer:     buffer,
		path:       scionPath,
	}
	result, err := p.process()
	if err != nil {
		// TODO(mawyss): Send back SCMP packet
		return processResult{}, err
	}

	isPenultimate := scionPath.IsPenultimateHop()
	isLast := scionPath.IsLastHop()

	if isPenultimate || isLast {
		timestamp := time.Unix(int64(info.Timestamp), 0)
		if err = libepic.VerifyTimestamp(timestamp, path.PktID.Timestamp, time.Now()); err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}

		HVF := path.PHVF
		if isLast {
			HVF = path.LHVF
		}
		if err = libepic.VerifyHVF(p.cachedMac, path.PktID, &s, info.Timestamp, HVF); err != nil {
			// TODO(mawyss): Send back SCMP packet
			return processResult{}, err
		}
	}

	return result, nil
}

type scionPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// ingressID is the interface ID this packet came in, determined from the
	// socket.
	ingressID uint16
	// rawPkt is the raw packet, it is updated during processing to contain the
	// message to send out.
	rawPkt []byte
	// scionLayer is the SCION gopacket layer.
	scionLayer slayers.SCION
	// origPacket is the raw original packet, must not be modified.
	origPacket []byte
	// buffer is the buffer that can be used to serialize gopacket layers.
	buffer gopacket.SerializeBuffer

	// path is the raw SCION path. Will be set during processing.
	path *scion.Raw
	// hopField is the current hopField field, is updated during processing.
	hopField *path.HopField
	// infoField is the current infoField field, is updated during processing.
	infoField *path.InfoField
	// segmentChange indicates if the path segment was changed during processing.
	segmentChange bool

	// cachedMac contains the full 16 bytes of the MAC. Will be set during processing.
	// For a hop performing an Xover, it is the MAC corresponding to the down segment.
	cachedMac []byte
}

func (p *scionPacketProcessor) packSCMP(scmpH *slayers.SCMP, scmpP gopacket.SerializableLayer,
	cause error) (processResult, error) {

	// parse everything to see if the original packet was an SCMP error.
	var (
		scionLayer slayers.SCION
		udpLayer   slayers.UDP
		hbhExtn    slayers.HopByHopExtn
		e2eExtn    slayers.EndToEndExtn
		scmpLayer  slayers.SCMP
	)
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION, &scionLayer, &udpLayer, &hbhExtn, &e2eExtn, &scmpLayer,
	)
	decoded := make([]gopacket.LayerType, 5)
	if err := parser.DecodeLayers(p.origPacket, &decoded); err != nil {
		if _, ok := err.(gopacket.UnsupportedLayerType); !ok {
			return processResult{}, serrors.WrapStr("decoding packet", err)
		}
	}
	// in reply to an SCMP error do nothing:
	if decoded[len(decoded)-1] == slayers.LayerTypeSCMP && !scmpLayer.TypeCode.InfoMsg() {
		return processResult{}, serrors.WrapStr("SCMP error for SCMP error pkt -> DROP", cause)
	}

	// the quoted packet is the packet in its current state
	if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
		return processResult{}, serrors.WrapStr("update info field", err)
	}
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return processResult{}, serrors.WrapStr("update hop field", err)
	}
	if err := p.buffer.Clear(); err != nil {
		return processResult{}, err
	}
	if err := p.scionLayer.SerializeTo(p.buffer, gopacket.SerializeOptions{}); err != nil {
		return processResult{}, err
	}
	// quoteLen is used to limit the size of the quote buffer, the final quote
	// length is calculated inside the scmpPacker.
	quoteLen := len(p.origPacket)
	if quoteLen > slayers.MaxSCMPPacketLen {
		quoteLen = slayers.MaxSCMPPacketLen
	}
	quote := make([]byte, quoteLen)
	updated := p.buffer.Bytes()
	copy(quote[:len(updated)], updated)
	copy(quote[len(updated):], p.origPacket[len(updated):quoteLen])

	_, external := p.d.external[p.ingressID]
	rawSCMP, err := scmpPacker{
		internalIP: p.d.internalIP,
		localIA:    p.d.localIA,
		origPacket: p.origPacket,
		ingressID:  p.ingressID,
		scionL:     &p.scionLayer,
		buffer:     p.buffer,
		quote:      quote,
	}.prepareSCMP(
		scmpH,
		scmpP,
		external,
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
		if err := updateSCIONLayer(p.rawPkt, p.scionLayer, p.buffer); err != nil {
			return err
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
	fullMac := path.FullMAC(p.d.macFactory(), p.infoField, p.hopField)
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

func (p *scionPacketProcessor) resolveInbound() (net.Addr, processResult, error) {
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
	if err := updateSCIONLayer(p.rawPkt, p.scionLayer, p.buffer); err != nil {
		return err
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
	if err := updateSCIONLayer(p.rawPkt, p.scionLayer, p.buffer); err != nil {
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

	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(p.scionLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
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

func (d *DataPlane) processOHP(ingressID uint16, rawPkt []byte, s slayers.SCION,
	buffer gopacket.SerializeBuffer) (processResult, error) {

	p, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return processResult{}, malformedPath
	}
	if !p.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return processResult{}, serrors.WrapStr(
			"OneHop path in reverse construction direction is not allowed",
			malformedPath, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}
	if !d.localIA.Equal(s.DstIA) && !d.localIA.Equal(s.SrcIA) {
		// TODO parameter problem -> invalid path
		return processResult{}, serrors.WrapStr("OneHop neither destined or originating from IA",
			cannotRoute, "localIA", d.localIA, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}
	// OHP leaving our IA
	if d.localIA.Equal(s.SrcIA) {
		mac := path.MAC(d.macFactory(), &p.Info, &p.FirstHop)
		if subtle.ConstantTimeCompare(p.FirstHop.Mac[:path.MacLen], mac) == 0 {
			// TODO parameter problem -> invalid MAC
			return processResult{}, serrors.New("MAC", "expected", fmt.Sprintf("%x", mac),
				"actual", fmt.Sprintf("%x", p.FirstHop.Mac[:path.MacLen]), "type", "ohp")
		}
		p.Info.UpdateSegID(p.FirstHop.Mac)

		if err := updateSCIONLayer(rawPkt, s, buffer); err != nil {
			return processResult{}, err
		}
		// OHP should always be directed to the correct BR.
		if c, ok := d.external[p.FirstHop.ConsEgress]; ok {
			// buffer should already be correct
			return processResult{EgressID: p.FirstHop.ConsEgress, OutConn: c, OutPkt: rawPkt}, nil
		}
		// TODO parameter problem invalid interface
		return processResult{}, serrors.WithCtx(cannotRoute, "type", "ohp",
			"egress", p.FirstHop.ConsEgress, "consDir", p.Info.ConsDir)
	}

	// OHP entering our IA
	p.SecondHop = path.HopField{
		ConsIngress: ingressID,
		ExpTime:     p.FirstHop.ExpTime,
	}
	p.SecondHop.Mac = path.MAC(d.macFactory(), &p.Info, &p.SecondHop)

	if err := updateSCIONLayer(rawPkt, s, buffer); err != nil {
		return processResult{}, err
	}
	a, err := d.resolveLocalDst(s)
	if err != nil {
		return processResult{}, err
	}
	return processResult{OutConn: d.internal, OutAddr: a, OutPkt: rawPkt}, nil
}

func (d *DataPlane) resolveLocalDst(s slayers.SCION) (net.Addr, error) {
	dst, err := s.DstAddr()
	if err != nil {
		// TODO parameter problem.
		return nil, err
	}
	if v, ok := dst.(addr.HostSVC); ok {
		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		a, ok := d.svc.Any(v.Base())
		if !ok {
			return nil, noSVCBackend
		}
		return a, nil
	}
	return addEndhostPort(dst), nil
}

func addEndhostPort(dst net.Addr) net.Addr {
	if ip, ok := dst.(*net.IPAddr); ok {
		return &net.UDPAddr{IP: ip.IP, Port: topology.EndhostPort}
	}
	return dst
}

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
	srcIA, dstIA     addr.IA
	macFactory       func() hash.Hash
	ifID             uint16
}

func (b *bfdSend) String() string {
	return b.srcAddr.String()
}

func (b *bfdSend) Send(bfd *layers.BFD) error {
	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4BFD,
		SrcIA:        b.srcIA,
		DstIA:        b.dstIA,
	}

	if err := scn.SetSrcAddr(&net.IPAddr{IP: b.srcAddr.IP}); err != nil {
		return err
	}
	if err := scn.SetDstAddr(&net.IPAddr{IP: b.dstAddr.IP}); err != nil {
		return err
	}

	if b.ifID == 0 {
		scn.PathType = empty.PathType
		scn.Path = &empty.Path{}
	} else {
		ohp := &onehop.Path{
			Info: path.InfoField{
				ConsDir: true,
				// Subtract 10 seconds to deal with possible clock drift.
				Timestamp: uint32(time.Now().Unix() - 10),
			},
			FirstHop: path.HopField{
				ConsEgress: b.ifID,
				ExpTime:    hopFieldDefaultExpTime,
			},
		}
		ohp.FirstHop.Mac = path.MAC(b.macFactory(), &ohp.Info, &ohp.FirstHop)
		scn.PathType = onehop.PathType
		scn.Path = ohp
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		scn, bfd)
	if err != nil {
		return err
	}
	msg := ipv4.Message{}
	msg.Buffers = make([][]byte, 1)
	raw := buffer.Bytes()
	msg.Buffers[0] = make([]byte, len(raw))
	copy(msg.Buffers[0], raw)
	msg.N = len(raw)
	msg.Addr = b.dstAddr
	_, err = b.conn.WriteBatch(underlayconn.Messages{msg})
	return err
}

type pathUpdater interface {
	update(p *scion.Raw) error
}

type scmpPacker struct {
	internalIP net.IP
	localIA    addr.IA
	origPacket []byte
	ingressID  uint16

	scionL *slayers.SCION
	buffer gopacket.SerializeBuffer
	quote  []byte
}

func (s scmpPacker) prepareSCMP(scmpH *slayers.SCMP, scmpP gopacket.SerializableLayer,
	external bool, cause error) ([]byte, error) {

	path, ok := s.scionL.Path.(*scion.Raw)
	if !ok {
		return nil, serrors.WithCtx(cannotRoute, "details", "unsupported path type",
			"path type", s.scionL.Path.Type())
	}

	decPath, err := path.ToDecoded()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "decoding raw path")
	}
	s.scionL.Path, err = decPath.Reverse()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := s.scionL.Path.(*scion.Decoded)

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() {
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	if external {
		infoField := revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := revPath.IncPath(); err != nil {
			return nil, serrors.Wrap(cannotRoute, err, "details", "incrementing path for SCMP")
		}
	}

	s.scionL.DstIA = s.scionL.SrcIA
	s.scionL.SrcIA = s.localIA
	srcA, err := s.scionL.SrcAddr()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "extracting src addr")
	}
	if err := s.scionL.SetDstAddr(srcA); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting dest addr")
	}
	if err := s.scionL.SetSrcAddr(&net.IPAddr{IP: s.internalIP}); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "setting src addr")
	}
	s.scionL.NextHdr = common.L4SCMP

	scmpH.SetNetworkLayerForChecksum(s.scionL)

	if err := s.buffer.Clear(); err != nil {
		return nil, err
	}

	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	scmpLayers := []gopacket.SerializableLayer{s.scionL, scmpH, scmpP}
	if cause != nil {
		// add quote for errors.
		hdrLen := slayers.CmnHdrLen + s.scionL.AddrHdrLen() + s.scionL.Path.Len()
		switch scmpH.TypeCode.Type() {
		case slayers.SCMPTypeExternalInterfaceDown:
			hdrLen += 20
		case slayers.SCMPTypeInternalConnectivityDown:
			hdrLen += 28
		default:
			hdrLen += 8
		}
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if len(s.quote) > maxQuoteLen {
			s.quote = s.quote[:maxQuoteLen]
		}
		scmpLayers = append(scmpLayers, gopacket.Payload(s.quote))
	}
	err = gopacket.SerializeLayers(s.buffer, sopts, scmpLayers...)
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "serializing SCMP message")
	}
	return s.buffer.Bytes(), scmpError{TypeCode: scmpH.TypeCode, Cause: cause}
}

type segIDUpdater struct{}

func (segIDUpdater) update(p *scion.Raw) error {
	cHF, err := p.GetCurrentHopField()
	if err != nil {
		return err
	}
	cIF, err := p.GetCurrentInfoField()
	if err != nil {
		return err
	}
	cIF.UpdateSegID(cHF.Mac)
	return nil
}

type pathIncrementer struct{}

func (pathIncrementer) update(p *scion.Raw) error {
	return p.IncPath()
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
