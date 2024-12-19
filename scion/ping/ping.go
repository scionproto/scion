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

// Package ping implements pinging based on SCMP echo messages.
package ping

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology/underlay"
)

// Stats contains the statistics of a ping run.
type Stats struct {
	Sent     int `json:"sent" yaml:"sent"`
	Received int `json:"received" yaml:"received"`
}

// Update contains intermediary information about a received echo reply
type Update struct {
	Size     int
	Source   snet.SCIONAddress
	Sequence int
	RTT      time.Duration
	State    State
}

// State indicates the state of the echo reply
type State int

// Possible states.
const (
	Success State = iota
	AfterTimeout
	OutOfOrder
	Duplicate
)

func (s State) String() string {
	switch s {
	case Success:
		return "success"
	case AfterTimeout:
		return "after_timeout"
	case OutOfOrder:
		return "out_of_order"
	case Duplicate:
		return "duplicate"
	default:
		return "unknown"
	}
}

// Config configures the ping run.
type Config struct {
	Local   addr.Addr
	Remote  addr.Addr
	Path    snet.DataplanePath
	NextHop *net.UDPAddr

	// Topology is the helper class to get control-plane information for the
	// local AS.
	Topology snet.Topology

	// Attempts is the number of pings to send.
	Attempts uint16
	// Interval is the time between sending pings.
	Interval time.Duration
	// Timeout is the time until a ping is considered to have timed out.
	Timeout time.Duration
	// PayloadSize is the size of the SCMP echo payload.
	PayloadSize int

	// ErrHandler is invoked for every error that does not cause pinging to
	// abort. Execution time must be small, as it is run synchronously.
	ErrHandler func(err error)
	// Update handler is invoked for every ping reply. Execution time must be
	// small, as it is run synchronously.
	UpdateHandler func(Update)
}

// Run ping with the configuration. This blocks until the configured number
// attempts is sent, or the context is canceled.
func Run(ctx context.Context, cfg Config) (Stats, error) {
	if cfg.Interval < time.Millisecond {
		return Stats{}, serrors.New("interval below millisecond")
	}

	replies := make(chan reply, 10)
	scmpHandler := &scmpHandler{
		replies: replies,
	}
	sn := &snet.SCIONNetwork{
		SCMPHandler: scmpHandler,
		Topology:    cfg.Topology,
	}
	// We need to manufacture a netip.UDPAddr as we're constrained by the sn API.
	netUdpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(cfg.Local.Host.IP(), 0))
	conn, err := sn.OpenRaw(ctx, netUdpAddr)
	if err != nil {
		return Stats{}, err
	}

	// Get our real local address and the port number we got.
	// We use the port as identifier on the handler.
	asNetipAddr, ok := netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		panic("Invalid Local IP address")
	}
	local := cfg.Local
	local.Host = addr.HostIP(asNetipAddr)
	id := conn.LocalAddr().(*net.UDPAddr).Port
	scmpHandler.SetId(id)

	// we need to have at least 8 bytes to store the request time in the
	// payload.
	if cfg.PayloadSize < 8 {
		cfg.PayloadSize = 8
	}
	p := pinger{
		attempts:      cfg.Attempts,
		interval:      cfg.Interval,
		timeout:       cfg.Timeout,
		pldSize:       cfg.PayloadSize,
		pld:           make([]byte, cfg.PayloadSize),
		id:            uint16(id),
		conn:          conn,
		local:         local,
		replies:       replies,
		errHandler:    cfg.ErrHandler,
		updateHandler: cfg.UpdateHandler,
	}
	return p.Ping(ctx, cfg.Remote, cfg.Path, cfg.NextHop)
}

type pinger struct {
	attempts uint16
	interval time.Duration
	timeout  time.Duration
	pldSize  int

	id      uint16
	conn    snet.PacketConn
	local   addr.Addr
	replies <-chan reply

	// Handlers
	errHandler    func(error)
	updateHandler func(Update)

	// Mutable state
	pld              []byte
	sentSequence     int
	receivedSequence int
	stats            Stats
}

func (p *pinger) Ping(
	ctx context.Context,
	remote addr.Addr,
	dPath snet.DataplanePath,
	nextHop *net.UDPAddr,
) (Stats, error) {

	p.sentSequence, p.receivedSequence = -1, -1
	send := time.NewTicker(p.interval)
	defer send.Stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errSend := make(chan error, 1)

	go func() {
		defer log.HandlePanic()
		p.drain(ctx)
	}()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		for i := uint16(0); i < p.attempts; i++ {
			if err := p.send(remote, dPath, nextHop); err != nil {
				errSend <- serrors.Wrap("sending", err)
				return
			}
			select {
			case <-send.C:
			case <-ctx.Done():
				return
			}
		}
		time.AfterFunc(p.timeout, cancel)
	}()

	for i := uint16(0); i < p.attempts; i++ {
		select {
		case <-ctx.Done():
			return p.stats, nil
		case err := <-errSend:
			return p.stats, err
		case reply := <-p.replies:
			if reply.Error != nil {
				if p.errHandler != nil {
					p.errHandler(reply.Error)
				}
				continue
			}
			p.receive(reply)
		}
	}
	wg.Wait()
	return p.stats, nil
}

func (p *pinger) send(remote addr.Addr, dPath snet.DataplanePath, nextHop *net.UDPAddr) error {
	sequence := p.sentSequence + 1

	binary.BigEndian.PutUint64(p.pld, uint64(time.Now().UnixNano()))
	pkt, err := pack(p.local, remote, dPath, snet.SCMPEchoRequest{
		Identifier: p.id,
		SeqNumber:  uint16(sequence),
		Payload:    p.pld,
	})
	if err != nil {
		return err
	}

	if nextHop == nil && p.local.IA.Equal(remote.IA) {
		nextHop = &net.UDPAddr{
			IP:   remote.Host.IP().AsSlice(),
			Port: underlay.EndhostPort,
			Zone: remote.Host.IP().Zone(),
		}

	}
	if err := p.conn.WriteTo(pkt, nextHop); err != nil {
		return err
	}

	p.sentSequence = sequence
	p.stats.Sent++
	return nil
}

func (p *pinger) receive(reply reply) {
	rtt := reply.Received.Sub(time.Unix(0, int64(binary.BigEndian.Uint64(reply.Reply.Payload)))).
		Round(time.Microsecond)
	var state State
	switch {
	case rtt > p.timeout:
		state = AfterTimeout
	case int(reply.Reply.SeqNumber) < p.receivedSequence:
		state = OutOfOrder
	case int(reply.Reply.SeqNumber) == p.receivedSequence:
		state = Duplicate
	default:
		state = Success
		p.receivedSequence = int(reply.Reply.SeqNumber)
	}
	p.stats.Received++
	if p.updateHandler != nil {
		p.updateHandler(Update{
			RTT:      rtt,
			Sequence: int(reply.Reply.SeqNumber),
			Size:     reply.Size,
			Source:   reply.Source,
			State:    state,
		})
	}
}

func (p *pinger) drain(ctx context.Context) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var pkt snet.Packet
			var ov net.UDPAddr
			if err := p.conn.ReadFrom(&pkt, &ov); err != nil && p.errHandler != nil {
				// Rate limit the error reports.
				if now := time.Now(); now.Sub(last) > 500*time.Millisecond {
					p.errHandler(serrors.Wrap("reading packet", err))
					last = now
				}
			}
		}
	}
}

type reply struct {
	Received time.Time
	Source   snet.SCIONAddress
	Size     int
	Reply    snet.SCMPEchoReply
	Error    error
}

type scmpHandler struct {
	id      uint16
	replies chan<- reply
}

func (h scmpHandler) Handle(pkt *snet.Packet) error {
	echo, err := h.handle(pkt)
	h.replies <- reply{
		Received: time.Now(),
		Source:   pkt.Source,
		Size:     len(pkt.Bytes),
		Reply:    echo,
		Error:    err,
	}
	return nil
}

func (h *scmpHandler) SetId(id int) {
	h.id = uint16(id)
}

func (h scmpHandler) handle(pkt *snet.Packet) (snet.SCMPEchoReply, error) {
	if pkt.Payload == nil {
		return snet.SCMPEchoReply{}, serrors.New("no v2 payload found")
	}
	switch s := pkt.Payload.(type) {
	case snet.SCMPEchoReply:
	case snet.SCMPExternalInterfaceDown:
		return snet.SCMPEchoReply{}, serrors.New("external interface is down",
			"isd_as", s.IA, "interface", s.Interface)
	case snet.SCMPInternalConnectivityDown:
		return snet.SCMPEchoReply{}, serrors.New("internal connectivity is down",
			"isd_as", s.IA, "ingress", s.Ingress, "egress", s.Egress)
	default:
		return snet.SCMPEchoReply{}, serrors.New("not SCMPEchoReply",
			"type", common.TypeOf(pkt.Payload),
		)
	}
	r := pkt.Payload.(snet.SCMPEchoReply)
	if r.Identifier != h.id {
		return snet.SCMPEchoReply{}, serrors.New("wrong SCMP ID",
			"expected", h.id, "actual", r.Identifier)
	}
	return r, nil
}
