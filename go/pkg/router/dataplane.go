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
	"crypto/rand"
	"errors"
	"hash"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/onehop"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/underlay/conn"
	underlayconn "github.com/scionproto/scion/go/lib/underlay/conn"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/router/bfd"
)

const (
	// Number of packets to read in a single ReadBatch call.
	inputBatchCnt = 64

	// TODO(karampok). Investigate whether that value should be higher.  In
	// theory, PayloadLen in SCION header is 16 bits long, supporting a maximum
	// payload size of 64KB. At the moment we are limited by Ethernet size
	// usually ~1500B, but 9000B to support jumbo frames.
	bufSize = 9000
)

type bfdSession interface {
	Run() error
	Messages() chan<- *layers.BFD
	IsUp() bool
}

// BatchConn is a connection that supports batch reads and writes.
type BatchConn interface {
	ReadBatch(underlayconn.Messages, []underlayconn.ReadMeta) (int, error)
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
	external         map[uint16]BatchConn
	internal         BatchConn
	internalIP       net.IP
	internalNextHops map[uint16]net.Addr
	svc              map[addr.HostSVC][]net.Addr
	macFactory       func() hash.Hash
	bfdSessions      map[uint16]bfdSession
	localIA          addr.IA
	mtx              sync.Mutex
	running          bool
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

// AddExternalInterfaceBFD adds the inter AS connection BFD session.
func (d *DataPlane) AddExternalInterfaceBFD(ifID uint16, conn BatchConn) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if conn == nil {
		return emptyValue
	}

	s := &bfdSend{
		conn: conn,
		addr: nil,
	}
	return d.addBFDController(ifID, s)
}

func (d *DataPlane) addBFDController(ifID uint16, s *bfdSend) error {
	// TODO(karampok). add extra argument as BFD params{} to set the timers.
	// TODO(karampok). make the local discriminator random.

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
		DetectMult:            3,
		Logger:                log.New("component", "BFD"),
		DesiredMinTxInterval:  1 * time.Millisecond,
		RequiredMinRxInterval: 25 * time.Millisecond,
		LocalDiscriminator:    disc,
		ReceiveQueueSize:      10,
	}

	return nil
}

// AddSvc adds the address for the given SVC. This can be called multiple times
// for the same service, with the address added to the list of addresses that
// provide the service. This can only be called on a not yet running dataplane.
func (d *DataPlane) AddSvc(svc addr.HostSVC, a net.Addr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}
	if a == nil {
		return emptyValue
	}
	if d.svc == nil {
		d.svc = make(map[addr.HostSVC][]net.Addr)
	}
	d.svc[svc] = append(d.svc[svc], a)
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
func (d *DataPlane) AddNextHopBFD(ifID uint16, a net.Addr) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.running {
		return modifyExisting
	}

	if a == nil {
		return emptyValue
	}

	for k, v := range d.internalNextHops {
		if v.String() == a.String() {
			if c, ok := d.bfdSessions[k]; ok {
				d.bfdSessions[ifID] = c
				return nil
			}
		}
	}

	s := &bfdSend{
		conn: d.internal,
		addr: a,
	}

	return d.addBFDController(ifID, s)
}

// Run starts running the dataplane. Note that configuration is not possible
// after calling this method.
func (d *DataPlane) Run() error {
	d.mtx.Lock()
	d.running = true

	read := func(ingressID uint16, rd BatchConn) {
		msgs := conn.NewReadMessages(inputBatchCnt)
		for _, msg := range msgs {
			msg.Buffers[0] = make([]byte, bufSize)
		}

		var scmpErr scmpError
		metas := make([]conn.ReadMeta, inputBatchCnt)
		spkt := slayers.SCION{}
		buffer := gopacket.NewSerializeBuffer()
		origPacket := make([]byte, bufSize)
		for d.running {
			pkts, err := rd.ReadBatch(msgs, metas)
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
				wr, err := d.processPkt(ingressID, &p, spkt, origPacket, buffer)
				switch {
				case err == nil:
				case errors.As(err, &scmpErr):
					if !scmpErr.TypeCode.InfoMsg() {
						log.Debug("SCMP", "err", scmpErr, "dst_addr", p.Addr)
					}
					// SCMP go back the way they came.
					wr = rd
					// SCMP metric?
				default:
					log.Debug("Error processing packet", "err", err)
					// error metric
					continue
				}
				if wr == nil { // e.g. BFD case no message is forwarded
					continue
				}
				_, err = wr.WriteBatch(underlayconn.Messages([]ipv4.Message{p}))
				if err != nil {
					log.Debug("Error writing packet", "err", err)
					// error metric
					continue
				}
				// ok metric
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
	for d.running {
		time.Sleep(time.Second)
	}
	return nil
}

func (d *DataPlane) processPkt(ingressID uint16, m *ipv4.Message, s slayers.SCION,
	origPacket []byte, buffer gopacket.SerializeBuffer) (BatchConn, error) {

	defer func() {
		// zero out the fields for sending:
		m.Flags = 0
		m.NN = 0
		m.N = 0
		m.OOB = nil
	}()

	if err := s.DecodeFromBytes(m.Buffers[0], gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	if err := buffer.Clear(); err != nil {
		return nil, serrors.WrapStr("Failed to clear buffer", err)
	}

	switch s.PathType {
	case slayers.PathTypeEmpty:
		if s.NextHdr == common.L4BFD {
			return nil, d.processBFD(ingressID, m.Addr, s.Payload)
		}
		return nil, serrors.WithCtx(unsupportedPathTypeNextHeader,
			"type", s.PathType, "header", s.NextHdr)
	case slayers.PathTypeOneHop:
		return d.processOHP(ingressID, m, s, buffer)
	case slayers.PathTypeSCION:
		return d.processSCION(ingressID, m, s, origPacket, buffer)
	default:
		return nil, serrors.WithCtx(unsupportedPathType, "type", s.PathType)
	}
}

func (d *DataPlane) processBFD(ingressID uint16, a net.Addr, data []byte) error {
	if len(d.bfdSessions) == 0 {
		return noBFDSessionConfigured
	}
	p := &layers.BFD{}
	if err := p.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	if ingressID == 0 && a == nil {
		return serrors.New("cannot receive packet without source address on internal interface")
	}
	if a != nil {
		for k, v := range d.internalNextHops {
			if v.String() == a.String() {
				ingressID = k
				continue
			}
		}
	}
	if v, ok := d.bfdSessions[ingressID]; ok {
		v.Messages() <- p
		return nil
	}
	return noBFDSessionFound
}

func (d *DataPlane) processSCION(ingressID uint16, m *ipv4.Message, s slayers.SCION,
	origPacket []byte, buffer gopacket.SerializeBuffer) (BatchConn, error) {

	p := scionPacketProcessor{
		d:          d,
		ingressID:  ingressID,
		m:          m,
		scionLayer: s,
		origPacket: origPacket,
		buffer:     buffer,
	}
	return p.process()
}

type scionPacketProcessor struct {
	// d is a reference to the dataplane instance that initiated this processor.
	d *DataPlane
	// ingressID is the interface ID this packet came in, determined from the
	// socket.
	ingressID uint16
	// m is the raw message, it is updated during processing to contain the
	// message to send out.
	m *ipv4.Message
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
}

func (p *scionPacketProcessor) packSCMP(scmpH *slayers.SCMP, scmpP gopacket.SerializableLayer,
	cause error) error {

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
			return serrors.WrapStr("decoding packet", err)
		}
	}
	// in reply to an SCMP error do nothing:
	if decoded[len(decoded)-1] == slayers.LayerTypeSCMP && !scmpLayer.TypeCode.InfoMsg() {
		return serrors.WrapStr("SCMP error for SCMP error pkt -> DROP", cause)
	}

	// the quoted packet is the packet in its current state
	if err := p.path.SetInfoField(p.infoField, int(p.path.PathMeta.CurrINF)); err != nil {
		return serrors.WrapStr("update info field", err)
	}
	if err := p.path.SetHopField(p.hopField, int(p.path.PathMeta.CurrHF)); err != nil {
		return serrors.WrapStr("update hop field", err)
	}
	if err := p.buffer.Clear(); err != nil {
		return err
	}
	if err := p.scionLayer.SerializeTo(p.buffer, gopacket.SerializeOptions{}); err != nil {
		return err
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
	if rawSCMP != nil {
		p.m.Buffers[0] = p.m.Buffers[0][:len(rawSCMP)]
		copy(p.m.Buffers[0], rawSCMP)
	}
	return err
}

func (p *scionPacketProcessor) parsePath() error {
	var ok bool
	p.path, ok = p.scionLayer.Path.(*scion.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return malformedPath
	}
	var err error
	p.hopField, err = p.path.GetCurrentHopField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return err
	}
	p.infoField, err = p.path.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return err
	}
	if err := p.validateHopExpiry(); err != nil {
		return err
	}
	if err := p.validateIngressID(); err != nil {
		return err
	}
	return nil
}

func (p *scionPacketProcessor) validateHopExpiry() error {
	expiration := util.SecsToTime(p.infoField.Timestamp).
		Add(spath.ExpTimeType(p.hopField.ExpTime).ToDuration())
	expired := expiration.Before(time.Now())
	if !expired {
		return nil
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

func (p *scionPacketProcessor) validateIngressID() error {
	pktIngressID := p.hopField.ConsIngress
	if !p.infoField.ConsDir {
		pktIngressID = p.hopField.ConsEgress
	}
	if p.ingressID != 0 && p.ingressID != pktIngressID {
		return p.packSCMP(
			&slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeUnknownHopFieldInterface),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.New("ingress interface invalid",
				"pkt_ingress", pktIngressID, "router_ingress", p.ingressID),
		)
	}
	return nil
}

func (p *scionPacketProcessor) validateEgressID() error {
	pktEgressID := p.egressInterface()
	_, ih := p.d.internalNextHops[pktEgressID]
	_, eh := p.d.external[pktEgressID]
	if !ih && !eh {
		return p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
					slayers.SCMPCodeUnknownHopFieldInterface),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			cannotRoute,
		)
	}
	return nil
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
		if err := updateSCIONLayer(p.m, p.scionLayer, p.buffer); err != nil {
			return err
		}
	}
	return nil
}

func (p *scionPacketProcessor) currentHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		scion.MetaLen + path.InfoLen*p.path.NumINF + path.HopLen*int(p.path.PathMeta.CurrHF))
}

func (p *scionPacketProcessor) verifyCurrentMAC() error {
	if err := path.VerifyMAC(p.d.macFactory(), p.infoField, p.hopField); err != nil {
		return p.packSCMP(
			&slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeInvalidHopFieldMAC),
			},
			&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
			serrors.WithCtx(err, "cons_dir", p.infoField.ConsDir, "if_id", p.ingressID,
				"curr_inf", p.path.PathMeta.CurrINF, "curr_hf", p.path.PathMeta.CurrHF,
				"seg_id", p.infoField.SegID),
		)
	}
	return nil
}

func (p *scionPacketProcessor) processInbound() error {
	var err error
	p.m.Addr, err = p.d.resolveLocalDst(p.scionLayer)
	switch {
	case errors.Is(err, noSVCBackend):
		return p.packSCMP(
			&slayers.SCMP{
				TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable,
					slayers.SCMPCodeNoRoute),
			},
			&slayers.SCMPDestinationUnreachable{}, err)
	default:
		return nil
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
	if err := updateSCIONLayer(p.m, p.scionLayer, p.buffer); err != nil {
		return err
	}

	p.m.Addr = nil
	return nil
}

func (p *scionPacketProcessor) doXover() error {
	if err := p.path.IncPath(); err != nil {
		// TODO parameter problem invalid path
		return serrors.WrapStr("incrementing path", err)
	}
	var err error
	if p.hopField, err = p.path.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return err
	}
	if p.infoField, err = p.path.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return err
	}
	if err := updateSCIONLayer(p.m, p.scionLayer, p.buffer); err != nil {
		return err
	}
	if err := p.validateHopExpiry(); err != nil {
		return err
	}
	// verify the new block
	if err := p.verifyCurrentMAC(); err != nil {
		return serrors.WithCtx(err, "info", "after xover")
	}
	return nil
}

func (p *scionPacketProcessor) egressInterface() uint16 {
	if p.infoField.ConsDir {
		return p.hopField.ConsEgress
	}
	return p.hopField.ConsIngress
}

func (p *scionPacketProcessor) validateEgressUp() error {
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
	return nil
}

func (p *scionPacketProcessor) handleIngressRouterAlert() error {
	if p.ingressID == 0 {
		return nil
	}
	ingressAlert := (!p.infoField.ConsDir && p.hopField.EgressRouterAlert) ||
		(p.infoField.ConsDir && p.hopField.IngressRouterAlert)
	if !ingressAlert {
		return nil
	}
	p.hopField.IngressRouterAlert = false
	return p.handleSCMPTraceRouteRequest(p.ingressID)
}

func (p *scionPacketProcessor) handleEgressRouterAlert() error {
	egressAlert := (p.infoField.ConsDir && p.hopField.EgressRouterAlert) ||
		(!p.infoField.ConsDir && p.hopField.IngressRouterAlert)
	if !egressAlert {
		return nil
	}
	egressID := p.egressInterface()
	if _, ok := p.d.external[egressID]; !ok {
		return nil
	}
	p.hopField.EgressRouterAlert = false
	return p.handleSCMPTraceRouteRequest(egressID)
}

func (p *scionPacketProcessor) handleSCMPTraceRouteRequest(interfaceID uint16) error {
	var scmpH slayers.SCMP
	if err := scmpH.DecodeFromBytes(p.scionLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
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
	scmpH = slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteReply, 0),
	}
	scmpP = slayers.SCMPTraceroute{
		Identifier: scmpP.Identifier,
		Sequence:   scmpP.Sequence,
		IA:         p.d.localIA,
		Interface:  uint64(interfaceID),
	}
	// XXX(lukedirtwalker): this is no really an error but we use error to
	// indicate SCMP to the root processing function.
	return p.packSCMP(&scmpH, &scmpP, nil)
}

func (p *scionPacketProcessor) validatePktLen() error {
	if int(p.scionLayer.PayloadLen) == len(p.scionLayer.Payload) {
		return nil
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

func (p *scionPacketProcessor) process() (BatchConn, error) {

	// TODO(karampok). Add various packet validations.
	if err := p.parsePath(); err != nil {
		return nil, err
	}
	if err := p.validatePktLen(); err != nil {
		return nil, err
	}
	if err := p.updateNonConsDirIngressSegID(); err != nil {
		return nil, err
	}
	if err := p.verifyCurrentMAC(); err != nil {
		return nil, err
	}
	if err := p.handleIngressRouterAlert(); err != nil {
		return nil, err
	}

	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA.Equal(p.d.localIA) && int(p.path.PathMeta.CurrHF)+1 == p.path.NumHops {
		if err := p.processInbound(); err != nil {
			return nil, err
		}
		return p.d.internal, nil
	}

	// Outbound: pkts leaving the local IA.
	// BRTransit: pkts leaving from the same BR different interface.

	if p.path.IsXover() {
		if err := p.doXover(); err != nil {
			return nil, err
		}
	}
	if err := p.validateEgressID(); err != nil {
		return nil, err
	}
	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if err := p.handleEgressRouterAlert(); err != nil {
		return nil, err
	}
	if err := p.validateEgressUp(); err != nil {
		return nil, err
	}

	egressID := p.egressInterface()
	if c, ok := p.d.external[egressID]; ok {
		if err := p.processEgress(); err != nil {
			return nil, err
		}
		return c, nil
	}

	// ASTransit: pkts leaving from another AS BR.
	if a, ok := p.d.internalNextHops[egressID]; ok {
		p.m.Addr = a
		return p.d.internal, nil
	}
	return nil, p.packSCMP(
		&slayers.SCMP{
			TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem,
				slayers.SCMPCodeUnknownHopFieldInterface),
		},
		&slayers.SCMPParameterProblem{Pointer: p.currentHopPointer()},
		cannotRoute,
	)
}

func (d *DataPlane) processOHP(ingressID uint16, m *ipv4.Message, s slayers.SCION,
	buffer gopacket.SerializeBuffer) (BatchConn, error) {

	p, ok := s.Path.(*onehop.Path)
	if !ok {
		// TODO parameter problem -> invalid path
		return nil, malformedPath
	}
	if !p.Info.ConsDir {
		// TODO parameter problem -> invalid path
		return nil, serrors.WrapStr("OneHop path in reverse construction direction is not allowed",
			malformedPath, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}
	if !d.localIA.Equal(s.DstIA) && !d.localIA.Equal(s.SrcIA) {
		// TODO parameter problem -> invalid path
		return nil, serrors.WrapStr("OneHop neither destined or originating from IA", cannotRoute,
			"localIA", d.localIA, "srcIA", s.SrcIA, "dstIA", s.DstIA)
	}
	// OHP leaving our IA
	if d.localIA.Equal(s.SrcIA) {
		if err := path.VerifyMAC(d.macFactory(), &p.Info, &p.FirstHop); err != nil {
			// TODO parameter problem -> invalid MAC
			return nil, serrors.WithCtx(err, "type", "ohp")
		}
		p.Info.UpdateSegID(p.FirstHop.Mac)

		if err := updateSCIONLayer(m, s, buffer); err != nil {
			return nil, err
		}
		// OHP should always be directed to the correct BR.
		if c, ok := d.external[p.FirstHop.ConsEgress]; ok {
			// buffer should already be correct
			m.Addr = nil
			return c, nil
		}
		// TODO parameter problem invalid interface
		return nil, serrors.WithCtx(cannotRoute, "type", "ohp",
			"egress", p.FirstHop.ConsEgress, "consDir", p.Info.ConsDir)
	}

	// OHP entering our IA
	p.SecondHop = path.HopField{
		ConsIngress: ingressID,
		ExpTime:     p.FirstHop.ExpTime,
	}
	p.SecondHop.Mac = path.MAC(d.macFactory(), &p.Info, &p.SecondHop)

	if err := updateSCIONLayer(m, s, buffer); err != nil {
		return nil, err
	}
	var err error
	m.Addr, err = d.resolveLocalDst(s)
	if err != nil {
		return nil, err
	}
	return d.internal, nil
}

func (d *DataPlane) resolveLocalDst(s slayers.SCION) (net.Addr, error) {
	dst, err := s.DstAddr()
	if err != nil {
		// TODO parameter problem.
		return nil, err
	}
	if v, ok := dst.(addr.HostSVC); ok {
		// TODO(karampok). We need to decide if we support multicast. They are
		// needed to support keepalives in a HA architecture, because we need
		// to make sure we hit the leader. If yes, then it requires significant
		// re-factor because the processPkt function cannot anymore return a
		// batchConn,error, but either an array and alternative approach (e.g.
		// write message to channel).

		// For map lookup use the Base address, i.e. strip the multi cast
		// information, because we only register base addresses in the map.
		if a, ok := d.svc[v.Base()]; ok {
			if len(a) > 0 {
				return addEndhostPort(a[0]), nil
			}
		}
		return nil, noSVCBackend
	}
	return addEndhostPort(dst), nil
}

func addEndhostPort(dst net.Addr) net.Addr {
	if ip, ok := dst.(*net.IPAddr); ok {
		return &net.UDPAddr{IP: ip.IP, Port: topology.EndhostPort}
	}
	return dst
}

func updateSCIONLayer(m *ipv4.Message, s slayers.SCION, buffer gopacket.SerializeBuffer) error {
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
	copy(m.Buffers[0][:len(rawContents)], rawContents)
	return nil
}

type bfdSend struct {
	conn BatchConn
	addr net.Addr
}

func (b *bfdSend) String() string {
	if b.addr == nil {
		return "external"
	}
	return b.addr.String()
}

func (b *bfdSend) Send(bfd *layers.BFD) error {
	// TODO(karampok). define the scion header for BFD messages.
	scn := &slayers.SCION{
		Version:      0,
		TrafficClass: 0xb8,
		FlowID:       0xdead,
		NextHdr:      common.L4BFD,
		PathType:     slayers.PathTypeEmpty,
		Path:         &scion.Decoded{},
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
	msg.Addr = b.addr
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
	incPath bool, cause error) ([]byte, error) {

	// We use the original packet but put the already updated path, because usually a router will
	// not keep a copy of the original/unmodified packet around.
	pathRaw := s.scionL.Path.(*scion.Raw).Raw

	if err := s.scionL.DecodeFromBytes(s.origPacket, gopacket.NilDecodeFeedback); err != nil {
		panic(err)
	}
	path := s.scionL.Path.(*scion.Raw)

	path.Raw = pathRaw
	decPath, err := path.ToDecoded()
	if err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "decoding raw path")
	}
	s.scionL.Path = decPath
	if err := decPath.Reverse(); err != nil {
		return nil, serrors.Wrap(cannotRoute, err, "details", "reversing path for SCMP")
	}
	if incPath {
		infoField := decPath.InfoFields[decPath.PathMeta.CurrINF]
		if infoField.ConsDir {
			hopField := decPath.HopFields[decPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.Mac)
		}
		if err := decPath.IncPath(); err != nil {
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
