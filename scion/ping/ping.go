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
	"sync"
	"time"

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
	Local  *snet.UDPAddr
	Remote *snet.UDPAddr

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

	sn := &snet.SCIONNetwork{
		Topology: cfg.Topology,
	}
	conn, err := sn.OpenRaw(ctx, cfg.Local.Host)
	if err != nil {
		return Stats{}, err
	}

	local := cfg.Local.Copy()
	local.Host = conn.LocalAddr().(*net.UDPAddr)

	// we set the identifier on the handler to the same value as
	// the udp port
	id := local.Host.Port

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
		replies:       make(chan reply, 10),
		errHandler:    cfg.ErrHandler,
		updateHandler: cfg.UpdateHandler,
	}
	return p.Ping(ctx, cfg.Remote)
}

type pinger struct {
	attempts uint16
	interval time.Duration
	timeout  time.Duration
	pldSize  int

	id      uint16
	conn    snet.PacketConn
	local   *snet.UDPAddr
	replies chan reply

	// Handlers
	errHandler    func(error)
	updateHandler func(Update)

	// Mutable state
	pld              []byte
	sentSequence     int
	receivedSequence int
	stats            Stats
}

func (p *pinger) Ping(ctx context.Context, remote *snet.UDPAddr) (Stats, error) {
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
			if err := p.send(remote); err != nil {
				errSend <- serrors.WrapStr("sending", err)
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

func (p *pinger) send(remote *snet.UDPAddr) error {
	sequence := p.sentSequence + 1

	binary.BigEndian.PutUint64(p.pld, uint64(time.Now().UnixNano()))
	pkt, err := pack(p.local, remote, snet.SCMPEchoRequest{
		Identifier: p.id,
		SeqNumber:  uint16(sequence),
		Payload:    p.pld,
	})
	if err != nil {
		return err
	}
	nextHop := remote.NextHop
	if nextHop == nil && p.local.IA.Equal(remote.IA) {
		nextHop = &net.UDPAddr{
			IP:   remote.Host.IP,
			Port: underlay.EndhostPort,
			Zone: remote.Host.Zone,
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
	var pkt snet.Packet
	var ov net.UDPAddr
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := p.conn.ReadFrom(&pkt, &ov); err != nil && p.errHandler != nil {
				// Rate limit the error reports.
				if now := time.Now(); now.Sub(last) > 500*time.Millisecond {
					p.errHandler(serrors.WrapStr("reading packet", err))
					last = now
				}
			}
			echo, err := toSCMPEchoReply(p.id, &pkt)
			p.replies <- reply{
				Received: time.Now(),
				Source:   pkt.Source,
				Size:     len(pkt.Bytes),
				Reply:    echo,
				Error:    err,
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

func toSCMPEchoReply(expectedId uint16, pkt *snet.Packet) (snet.SCMPEchoReply, error) {
	switch r := pkt.Payload.(type) {
	case snet.SCMPEchoReply:
		if r.Identifier != expectedId {
			return snet.SCMPEchoReply{}, serrors.New("wrong SCMP ID",
				"expected", expectedId, "actual", r.Identifier)
		}
		return r, nil
	case snet.SCMPExternalInterfaceDown:
		return snet.SCMPEchoReply{}, serrors.New("external interface is down",
			"isd_as", r.IA, "interface", r.Interface)
	case snet.SCMPInternalConnectivityDown:
		return snet.SCMPEchoReply{}, serrors.New("internal connectivity is down",
			"isd_as", r.IA, "ingress", r.Ingress, "egress", r.Egress)
	default:
		return snet.SCMPEchoReply{}, serrors.New("not SCMPEchoReply",
			"type", common.TypeOf(pkt.Payload),
		)
	}
}
