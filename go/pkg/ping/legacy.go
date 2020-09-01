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

package ping

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

type legacyPinger struct {
	attempts uint16
	interval time.Duration
	timeout  time.Duration
	pldSize  int

	id      uint64
	conn    snet.PacketConn
	local   *snet.UDPAddr
	replies <-chan legacyReply

	// Handlers
	errHandler    func(error)
	updateHandler func(Update)

	// Mutable state
	pld              []byte
	sentSequence     int
	receivedSequence int
	stats            Stats
}

func (p *legacyPinger) Ping(ctx context.Context, remote *snet.UDPAddr) (Stats, error) {
	p.sentSequence, p.receivedSequence = -1, -1
	send := time.NewTicker(p.interval)
	defer send.Stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer log.HandlePanic()
		p.drain(ctx)
	}()

	for i := uint16(0); i < p.attempts; i++ {
		select {
		case <-ctx.Done():
			return p.stats, nil
		case <-send.C:
			if err := p.send(remote); err != nil {
				return p.stats, serrors.WrapStr("sending", err)
			}
		case reply := <-p.replies:
			if reply.Error != nil {
				if p.errHandler != nil {
					p.errHandler(reply.Error)
				}
				continue
			}
			p.legacyReceive(reply)
		}
	}
	return p.stats, nil

}

func (p *legacyPinger) send(remote *snet.UDPAddr) error {
	sequence := p.sentSequence + 1

	pkt, err := newEcho(p.local, remote, p.pldSize,
		scmp.InfoEcho{Id: p.id, Seq: uint16(sequence)})
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

func (p *legacyPinger) legacyReceive(reply legacyReply) {
	rtt := reply.Received.Sub(reply.Header.Time()).Round(time.Microsecond)
	var state State
	switch {
	case rtt > p.timeout:
		state = AfterTimeout
	case int(reply.Info.Seq) < p.receivedSequence:
		state = OutOfOrder
	case int(reply.Info.Seq) == p.receivedSequence:
		state = Duplicate
	default:
		state = Success
		p.receivedSequence = int(reply.Info.Seq)
	}
	p.stats.Received++
	if p.updateHandler != nil {
		p.updateHandler(Update{
			RTT:      rtt,
			Sequence: int(reply.Info.Seq),
			Size:     reply.Size,
			Source:   reply.Source,
			State:    state,
		})
	}
}

func (p *legacyPinger) drain(ctx context.Context) {
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
					p.errHandler(serrors.WrapStr("reading packet", err))
					last = now
				}
			}
		}
	}
}

type legacyReply struct {
	Received time.Time
	Source   snet.SCIONAddress
	Size     int
	Header   *scmp.Hdr
	Info     *scmp.InfoEcho
	Error    error
}

type legacySCMPHandler struct {
	id      uint64
	replies chan<- legacyReply
}

func (h legacySCMPHandler) Handle(pkt *snet.Packet) error {
	hdr, info, err := h.handle(pkt)
	h.replies <- legacyReply{
		Error:    err,
		Header:   hdr,
		Size:     len(pkt.Bytes),
		Source:   pkt.Source,
		Info:     info,
		Received: time.Now(),
	}
	return nil
}

func (h legacySCMPHandler) handle(pkt *snet.Packet) (*scmp.Hdr, *scmp.InfoEcho, error) {
	scmpHdr, ok := pkt.L4Header.(*scmp.Hdr)
	if !ok {
		return nil, nil, serrors.New("not an SCMP header", "type", common.TypeOf(pkt.L4Header))

	}
	scmpPld, ok := pkt.PacketInfo.Payload.(*scmp.Payload)
	if !ok {
		return scmpHdr, nil,
			serrors.New("not an SCMP payload", "type", common.TypeOf(pkt.Payload))
	}
	info, ok := scmpPld.Info.(*scmp.InfoEcho)
	if !ok {
		return nil, nil, serrors.New("not an echo", "type", common.TypeOf(scmpPld.Info))
	}
	if info.Id != h.id {
		return nil, nil, serrors.New("wrong SCMP ID", "expected", h.id, "actual", info.Id)
	}
	return scmpHdr, info, nil
}
