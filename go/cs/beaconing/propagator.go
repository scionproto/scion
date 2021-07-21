// Copyright 2019 Anapaya Systems
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

package beaconing

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	// DefaultRPCTimeout is the default silent time SCION RPC Clients will wait
	// for before declaring a timeout. Most RPCs will be subject to an
	// additional context, and the timeout will be the minimum value allowed by
	// the context and this timeout. RPC clients are free to use a different
	// timeout if they have special requirements.
	DefaultRPCTimeout time.Duration = 10 * time.Second
)

// BeaconProvider provides beacons to send to neighboring ASes.
type BeaconProvider interface {
	BeaconsToPropagate(ctx context.Context) ([]beacon.Beacon, error)
}

var _ periodic.Task = (*Propagator)(nil)

// Propagator forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	Extender              Extender
	SenderFactory         SenderFactory
	Provider              BeaconProvider
	IA                    addr.IA
	Signer                seg.Signer
	AllInterfaces         *ifstate.Interfaces
	PropagationInterfaces func() []*ifstate.Interface
	AllowIsdLoop          bool

	Propagated     metrics.Counter
	InternalErrors metrics.Counter

	// Tick is mutable.
	Tick Tick
}

// Name returns the tasks name.
func (p *Propagator) Name() string {
	return "control_beaconing_propagator"
}

// Run propagates beacons provided by the beacon provider on all active target
// interfaces. In a core beacon server, core interfaces are the target
// interfaces. In a non-core beacon server, child interfaces are the target
// interfaces.
func (p *Propagator) Run(ctx context.Context) {
	p.Tick.SetNow(time.Now())
	logger := log.FromCtx(ctx)
	if err := p.run(ctx, logger); err != nil {
		logger.Error("Unable to propagate beacons", "err", err)
	}
	p.Tick.UpdateLast()
}

func (p *Propagator) run(ctx context.Context, logger log.Logger) error {
	intfs := p.needsBeacons(logger)
	if len(intfs) == 0 {
		return nil
	}
	peers := sortedIntfs(p.AllInterfaces, topology.Peer)
	beacons, err := p.Provider.BeaconsToPropagate(ctx)
	if err != nil {
		p.incrementInternalErrors()
		return err
	}
	var toPropagate []beacon.Beacon
	for _, b := range beacons {
		if p.AllInterfaces.Get(b.InIfId) == nil {
			continue
		}
		toPropagate = append(toPropagate, b)
	}
	b := propagator{
		Propagator: p,
		beacons:    toPropagate,
		intfs:      intfs,
		peers:      peers,
		logger:     logger,
	}
	if err := b.propagate(ctx); err != nil {
		return serrors.WrapStr("error propagating", err, "beacons", b.beacons)
	}
	return nil
}

// needsBeacons returns a list of active interfaces that beacons should be
// propagated on. In a core AS, these are all active core links. In a non-core
// AS, these are all active child links.
func (p *Propagator) needsBeacons(logger log.Logger) []*ifstate.Interface {
	intfs := p.PropagationInterfaces()
	sort.Slice(intfs, func(i, j int) bool {
		return intfs[i].TopoInfo().ID < intfs[j].TopoInfo().ID
	})

	if p.Tick.Passed() {
		return intfs
	}
	stale := make([]*ifstate.Interface, 0, len(intfs))
	for _, intf := range intfs {
		if p.Tick.Overdue(intf.LastPropagate()) {
			stale = append(stale, intf)
		}
	}
	return stale
}

func (p *Propagator) incrementInternalErrors() {
	if p.InternalErrors == nil {
		return
	}
	p.InternalErrors.Add(1)
}

// propagator propagates a set of beacons on all active interfaces.
type propagator struct {
	*Propagator
	wg      sync.WaitGroup
	beacons []beacon.Beacon
	intfs   []*ifstate.Interface
	peers   []common.IFIDType
	success ctr
	logger  log.Logger
}

// propagate propagates beacons on all active interfaces.
func (p *propagator) propagate(ctx context.Context) error {
	var expected int
	for _, intf := range p.intfs {
		var toPropagate []beacon.Beacon
		for _, b := range p.beacons {
			if p.shouldIgnore(b, intf) {
				continue
			}
			expected++
			// Create a "copy" from the original beacon to avoid races on the
			// ASEntry slice.
			ps, err := seg.BeaconFromPB(seg.PathSegmentToPB(b.Segment))
			if err != nil {
				p.Propagator.incrementInternalErrors()
				p.logger.Debug("Unable to unpack beacon", "err", err)
				continue
			}
			toPropagate = append(toPropagate, beacon.Beacon{Segment: ps, InIfId: b.InIfId})
		}
		p.extendAndSend(ctx, toPropagate, intf)
	}
	p.wg.Wait()
	if expected == 0 {
		return nil
	}
	if p.success.c <= 0 {
		return serrors.New("no beacon propagated", "expected", expected)
	}
	p.logger.Debug("Successfully propagated", "beacons", p.beacons, "interfaces", p.intfs,
		"expected", expected, "count", p.success.c)
	return nil
}

// extendAndSend extends the path segment with the AS entry and sends it on the
// egress interface, all done in a goroutine to avoid head-of-line blocking.
func (p *propagator) extendAndSend(
	ctx context.Context,
	bsegs []beacon.Beacon,
	intf *ifstate.Interface,
) {
	if len(bsegs) == 0 {
		return
	}
	egIfid := intf.TopoInfo().ID
	p.wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer p.wg.Done()

		var toPropagate []beacon.Beacon
		for _, bseg := range bsegs {
			err := p.Extender.Extend(ctx, bseg.Segment, bseg.InIfId, egIfid, p.peers)
			if err != nil {
				p.logger.Error("Unable to extend beacon", "beacon", bseg, "err", err)
				p.incMetric(bseg.Segment.FirstIA(), bseg.InIfId, egIfid, "err_create")
				continue
			}
			toPropagate = append(toPropagate, bseg)
		}
		topoInfo := intf.TopoInfo()

		rpcContext, cancelF := context.WithTimeout(ctx, DefaultRPCTimeout)
		defer cancelF()

		rpcStart := time.Now()
		sender, err := p.SenderFactory.NewSender(rpcContext, topoInfo.IA, uint16(egIfid),
			topoInfo.InternalAddr)
		if err != nil {
			if rpcContext.Err() != nil {
				err = serrors.WrapStr("timed out getting beacon sender", err,
					"waited_for", time.Since(rpcStart))
			}
			p.logger.Info("Unable to propagate beacons", "egress_interface", egIfid, "err", err)
			for _, b := range toPropagate {
				p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
			}
			return
		}
		defer sender.Close()

		successes := 0
		for _, b := range toPropagate {
			if err := sender.Send(rpcContext, b.Segment); err != nil {
				if rpcContext.Err() != nil {
					err = serrors.WrapStr("timed out waiting for RPC to complete", err,
						"waited_for", time.Since(rpcStart))
					p.logger.Info("Unable to propagate beacons", "egress_interface", egIfid,
						"err", err)
					p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
					// Return here if the context is expired, since no RPC will complete at that
					// point.
					return
				}
				p.logger.Info("Unable to propagate beacons", "egress_interface", egIfid, "err", err)
				p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
				continue
			}
			p.onSuccess(intf, egIfid)
			p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.Success)
			successes++
		}
		p.logger.Debug("Propagated beacons", "egress_interface", egIfid, "expected",
			len(toPropagate), "successes", successes)
	}()
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *propagator) shouldIgnore(bseg beacon.Beacon, intf *ifstate.Interface) bool {
	if err := beacon.FilterLoop(bseg, intf.TopoInfo().IA, p.AllowIsdLoop); err != nil {
		return true
	}
	return false
}

func (p *propagator) onSuccess(intf *ifstate.Interface, egIfid common.IFIDType) {
	intf.Propagate(p.Tick.Now())
	p.success.Inc()
}

func (p *propagator) incMetric(startIA addr.IA, ingress, egress common.IFIDType, result string) {
	if p.Propagator.Propagated == nil {
		return
	}
	p.Propagator.Propagated.With(
		"start_isd_as", startIA.String(),
		"ingress_interface", strconv.Itoa(int(ingress)),
		"egress_interface", strconv.Itoa(int(egress)),
		prom.LabelResult, result,
	).Add(1)
}
