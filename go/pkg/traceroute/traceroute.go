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

// Package traceroute implements tracerouting based on SCMP traceroute messages.
package traceroute

import (
	"context"
	"math/rand"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

// Update contains the information for a single hop.
type Update struct {
	// Index indicates the hop index in the path.
	Index int
	// Remote is the remote router.
	Remote *snet.UDPAddr
	// Interface is the interface ID of the remote router.
	Interface uint64
	// RTTs are the RTTs for this hop. To detect whether there was a timeout the
	// value of the RTT can be compared against the timeout value from the
	// configuration.
	RTTs []time.Duration
}

func (u Update) empty() bool {
	return u.Index == 0 && u.Remote == nil && u.Interface == 0 && len(u.RTTs) == 0
}

// Stats contains the amount of sent and received packets.
type Stats struct {
	Sent, Recv uint
}

// Config configures the traceroute run.
type Config struct {
	Dispatcher  reliable.Dispatcher
	Local       *snet.UDPAddr
	MTU         uint16
	PathEntry   snet.Path
	PayloadSize uint
	Remote      *snet.UDPAddr
	Timeout     time.Duration

	// ProbesPerHop indicates how many probes should be done per hop.
	ProbesPerHop int
	// ErrHandler is invoked for every error that does not cause tracerouting to
	// abort. Execution time must be small, as it is run synchronously.
	ErrHandler func(error)
	// Update handler is invoked for every hop. Execution time must be
	// small, as it is run synchronously.
	UpdateHandler func(Update)
}

type tracerouter struct {
	probesPerHop  int
	timeout       time.Duration
	conn          snet.PacketConn
	local         *snet.UDPAddr
	remote        *snet.UDPAddr
	errHandler    func(error)
	updateHandler func(Update)

	replies <-chan reply

	path  snet.Path
	id    uint16
	index int

	stats Stats
}

// Run runs the traceroute.
func Run(ctx context.Context, cfg Config) (Stats, error) {
	if cfg.PathEntry.Path().IsEmpty() {
		return Stats{}, serrors.New("empty path is not allowed for traceroute")
	}
	id := rand.Uint64()
	replies := make(chan reply, 10)
	dispatcher := snet.DefaultPacketDispatcherService{
		Dispatcher:  cfg.Dispatcher,
		SCMPHandler: scmpHandler{replies: replies},
	}
	conn, port, err := dispatcher.Register(ctx, cfg.Local.IA, cfg.Local.Host, addr.SvcNone)
	if err != nil {
		return Stats{}, err
	}
	local := cfg.Local.Copy()
	local.Host.Port = int(port)
	t := tracerouter{
		probesPerHop:  cfg.ProbesPerHop,
		timeout:       cfg.Timeout,
		conn:          conn,
		local:         local,
		remote:        cfg.Remote,
		replies:       replies,
		errHandler:    cfg.ErrHandler,
		updateHandler: cfg.UpdateHandler,
		id:            uint16(id),
		path:          cfg.PathEntry,
	}
	return t.Traceroute(ctx)
}

func (t *tracerouter) Traceroute(ctx context.Context) (Stats, error) {
	pktPath := scion.Decoded{}
	if err := pktPath.DecodeFromBytes(t.path.Path().Raw); err != nil {
		return t.stats, serrors.WrapStr("decoding path", err)
	}
	idxPath := scion.Decoded{}
	if err := idxPath.DecodeFromBytes(t.path.Path().Raw); err != nil {
		return t.stats, serrors.WrapStr("decoding path", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer log.HandlePanic()
		t.drain(ctx)
	}()
	prevXover := false
	for i := 0; i < len(idxPath.HopFields); i++ {
		hf := pktPath.HopFields[idxPath.PathMeta.CurrHF]
		info := pktPath.InfoFields[idxPath.PathMeta.CurrINF]
		// First hop of the path isn't probed, since only the egress hop is
		// relevant.
		// After a crossover (segment change) only the egress interface is
		// relevant, since the ingress interface is in previous hop.
		if i != 0 && !prevXover {
			u, err := t.probeHop(ctx, &pktPath, hf, !info.ConsDir)
			if err != nil {
				return t.stats, serrors.WrapStr("probing hop", err, "hop_index", i)
			}
			if t.updateHandler != nil && !u.empty() {
				t.updateHandler(u)
			}
		}
		xover := idxPath.IsXover()
		// The last hop of the path isn't probed, only the ingress interface is
		// relevant.
		// At a crossover (segment change) only the ingress interface is
		// relevant, since the egress interface is in the next hop.
		if i < len(idxPath.HopFields)-1 && !xover {
			u, err := t.probeHop(ctx, &pktPath, hf, info.ConsDir)
			if err != nil {
				return t.stats, serrors.WrapStr("probing hop", err, "hop_index", i)
			}
			if t.updateHandler != nil && !u.empty() {
				t.updateHandler(u)
			}
		}
		if i < len(idxPath.HopFields)-1 {
			if err := idxPath.IncPath(); err != nil {
				return t.stats, serrors.WrapStr("incrementing path", err)
			}
		}
		prevXover = xover
	}
	return t.stats, nil
}

func (t *tracerouter) probeHop(ctx context.Context, dp *scion.Decoded,
	hf *path.HopField, egress bool) (Update, error) {

	// set alert flag and reset once we are done.
	if egress {
		hf.EgressRouterAlert = true
		defer func() { hf.EgressRouterAlert = false }()
	} else {
		hf.IngressRouterAlert = true
		defer func() { hf.IngressRouterAlert = false }()
	}
	p := t.path.Path()
	if err := dp.SerializeTo(p.Raw); err != nil {
		return Update{}, serrors.WrapStr("serializing path", err)
	}
	u := Update{
		Index: t.index,
		RTTs:  make([]time.Duration, 0, t.probesPerHop),
	}
	t.index++
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   t.remote.IA,
				Host: addr.HostFromIP(t.remote.Host.IP),
			},
			Source: snet.SCIONAddress{
				IA:   t.local.IA,
				Host: addr.HostFromIP(t.local.Host.IP),
			},
			Path:    p,
			Payload: snet.SCMPTracerouteRequest{Identifier: t.id},
		},
	}
	for i := 0; i < t.probesPerHop; i++ {
		sendTs := time.Now()
		t.stats.Sent++
		if err := t.conn.WriteTo(pkt, t.remote.NextHop); err != nil {
			return u, serrors.WrapStr("writing", err)
		}
		select {
		case <-time.After(t.timeout):
			u.RTTs = append(u.RTTs, t.timeout+1)
			continue
		case reply := <-t.replies:
			if reply.Error != nil {
				if t.errHandler != nil {
					t.errHandler(reply.Error)
				}
				continue
			}
			if t.id != reply.Reply.Identifier {
				if t.errHandler != nil {
					t.errHandler(serrors.New("wrong SCMP ID",
						"expected", t.id, "actual", reply.Reply.Identifier))
				}
				continue
			}
			t.stats.Recv++
			rtt := reply.Received.Sub(sendTs).Round(time.Microsecond)
			u.RTTs = append(u.RTTs, rtt)
			u.Interface = reply.Reply.Interface
			u.Remote = reply.Remote
		case <-ctx.Done():
			return u, nil
		}
	}
	return u, nil
}

func (t tracerouter) drain(ctx context.Context) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var pkt snet.Packet
			var ov net.UDPAddr
			if err := t.conn.ReadFrom(&pkt, &ov); err != nil && t.errHandler != nil {
				// Rate limit the error reports.
				if now := time.Now(); now.Sub(last) > 500*time.Millisecond {
					t.errHandler(serrors.WrapStr("reading packet", err))
					last = now
				}
			}
		}
	}
}

type reply struct {
	Received time.Time
	Reply    snet.SCMPTracerouteReply
	Remote   *snet.UDPAddr
	Error    error
}

type scmpHandler struct {
	replies chan<- reply
}

func (h scmpHandler) Handle(pkt *snet.Packet) error {
	r, err := h.handle(pkt)
	h.replies <- reply{
		Received: time.Now(),
		Reply:    r,
		Remote: &snet.UDPAddr{
			IA:   pkt.Source.IA,
			Host: &net.UDPAddr{IP: pkt.Destination.Host.IP()},
			Path: pkt.Path.Copy(),
		},
		Error: err,
	}
	return nil
}

func (h scmpHandler) handle(pkt *snet.Packet) (snet.SCMPTracerouteReply, error) {
	if pkt.Payload == nil {
		return snet.SCMPTracerouteReply{}, serrors.New("no payload found")
	}
	r, ok := pkt.Payload.(snet.SCMPTracerouteReply)
	if !ok {
		return snet.SCMPTracerouteReply{}, serrors.New("not SCMPTracerouteReply",
			"type", common.TypeOf(pkt.Payload))
	}
	return r, nil
}
