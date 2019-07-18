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
	"sync"
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/beaconing/metrics"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/proto"
)

// BeaconProvider provides beacons to send to neighboring ASes.
type BeaconProvider interface {
	BeaconsToPropagate(ctx context.Context) (<-chan beacon.BeaconOrErr, error)
}

var _ periodic.Task = (*Propagator)(nil)

// PropagatorConf is the configuration to create a new propagator.
type PropagatorConf struct {
	Config         ExtenderConf
	BeaconProvider BeaconProvider
	BeaconSender   *onehop.BeaconSender
	Period         time.Duration
	Core           bool
	AllowIsdLoop   bool
	EnableMetrics  bool
}

// Propagator forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	*segExtender
	beaconSender *onehop.BeaconSender
	provider     BeaconProvider
	metrics      *metrics.Propagator
	allowIsdLoop bool
	core         bool

	// tick is mutable.
	tick tick
}

// New creates a new beacon propagation task.
func (cfg PropagatorConf) New() (*Propagator, error) {
	cfg.Config.task = "propagator"
	extender, err := cfg.Config.new()
	if err != nil {
		return nil, err
	}
	p := &Propagator{
		provider:     cfg.BeaconProvider,
		beaconSender: cfg.BeaconSender,
		core:         cfg.Core,
		allowIsdLoop: cfg.AllowIsdLoop,
		segExtender:  extender,
		tick:         tick{period: cfg.Period},
	}
	if cfg.EnableMetrics {
		p.metrics = metrics.InitPropagator()
	}
	return p, nil
}

// Run propagates beacons provided by the beacon provider on all active target
// interfaces. In a core beacon server, core interfaces are the target
// interfaces. In a non-core beacon server, child interfaces are the target
// interfaces.
func (p *Propagator) Run(ctx context.Context) {
	p.tick.now = time.Now()
	if err := p.run(ctx); err != nil {
		log.Error("[Propagator] Unable to propagate beacons", "err", err)
	}
	p.tick.updateLast()
	p.metrics.AddTotalTime(p.tick.now)
}

func (p *Propagator) run(ctx context.Context) error {
	intfs := p.needsBeacons()
	if len(intfs) == 0 {
		return nil
	}
	peers, nonActivePeers := sortedIntfs(p.cfg.Intfs, proto.LinkType_peer)
	if len(nonActivePeers) > 0 && p.tick.passed() {
		log.Debug("[Propagator] Ignore non-active peering interfaces", "ifids", nonActivePeers)
	}
	beacons, err := p.provider.BeaconsToPropagate(ctx)
	if err != nil {
		p.metrics.IncInternalErr()
		return err
	}
	s := newSummary()
	var wg sync.WaitGroup
	for bOrErr := range beacons {
		if bOrErr.Err != nil {
			log.Error("[Propagator] Unable to get beacon", "err", bOrErr.Err)
			p.metrics.IncInternalErr()
			continue
		}
		b := beaconPropagator{
			Propagator:  p,
			beacon:      bOrErr.Beacon,
			activeIntfs: intfs,
			peers:       peers,
			summary:     s,
		}
		b.start(ctx, &wg)
	}
	wg.Wait()
	p.logSummary(s)
	return nil
}

// needsBeacons returns a list of active interface ids that beacons should be
// propagated to. In a core AS, these are all active core links. In a non-core
// AS, these are all active child links.
func (p *Propagator) needsBeacons() []common.IFIDType {
	var activeIntfs, nonActiveIntfs []common.IFIDType
	if p.core {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.cfg.Intfs, proto.LinkType_core)
	} else {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.cfg.Intfs, proto.LinkType_child)
	}
	if len(nonActiveIntfs) > 0 && p.tick.passed() {
		log.Debug("[Propagator] Ignore non-active interfaces", "ifids", nonActiveIntfs)
	}
	if p.tick.passed() {
		return activeIntfs
	}
	stale := make([]common.IFIDType, 0, len(activeIntfs))
	for _, ifid := range activeIntfs {
		intf := p.cfg.Intfs.Get(ifid)
		if intf == nil {
			continue
		}
		if p.tick.now.Sub(intf.LastPropagate()) > p.tick.period {
			stale = append(stale, ifid)
		}
	}
	return stale
}

func (p *Propagator) logSummary(s *summary) {
	if p.tick.passed() {
		log.Info("[Propagator] Propagated beacons", "count", s.count, "startIAs", len(s.srcs),
			"egIfIds", s.IfIds())
		return
	}
	if s.count > 0 {
		log.Info("[Propagator] Propagated beacons on stale interfaces", "count", s.count,
			"startIAs", len(s.srcs), "egIfIds", s.IfIds())
	}
}

// beaconPropagator propagates one beacon to all active interfaces.
type beaconPropagator struct {
	*Propagator
	wg          sync.WaitGroup
	beacon      beacon.Beacon
	activeIntfs []common.IFIDType
	peers       []common.IFIDType
	success     ctr
	summary     *summary
}

// start adds to the wait group and starts propagation of the beacon on
// all active interfaces.
func (p *beaconPropagator) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.propagate(ctx); err != nil {
			log.Error("[Propagator] Unable to propagate", "beacon", p.beacon, "err", err)
			return
		}
	}()
}

func (p *beaconPropagator) propagate(ctx context.Context) error {
	raw, err := p.beacon.Segment.Pack()
	if err != nil {
		p.metrics.IncInternalErr()
		return err
	}
	var expected int
	for _, egIfid := range p.activeIntfs {
		if p.shouldIgnore(p.beacon, egIfid) {
			continue
		}
		expected++
		bseg := p.beacon
		if bseg.Segment, err = seg.NewBeaconFromRaw(raw); err != nil {
			p.metrics.IncInternalErr()
			return common.NewBasicError("Unable to unpack beacon", err)
		}
		p.extendAndSend(ctx, bseg, egIfid)
	}
	p.wg.Wait()
	if expected == 0 {
		return nil
	}
	if p.success.c <= 0 {
		return common.NewBasicError("None propagated", nil, "expected", expected)
	}
	p.summary.AddSrc(p.beacon.Segment.FirstIA())
	p.summary.Inc()
	log.Trace("[Propagator] Successfully propagated", "beacon", p.beacon,
		"expected", expected, "count", p.success.c)
	return nil
}

// extendAndSend extends the path segment with the AS entry and sends it on the
// egress interface, all done in a goroutine to avoid head-of-line blocking.
func (p *beaconPropagator) extendAndSend(ctx context.Context, bseg beacon.Beacon,
	egIfid common.IFIDType) {

	p.wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer p.wg.Done()
		defer p.metrics.AddIntfTime(bseg.Segment.FirstIA(), bseg.InIfId, egIfid, time.Now())
		if err := p.extend(bseg.Segment, bseg.InIfId, egIfid, p.peers); err != nil {
			log.Error("[Propagator] Unable to extend beacon", "beacon", bseg, "err", err)
			p.metrics.IncTotalBeacons(bseg.Segment.FirstIA(), bseg.InIfId, egIfid,
				metrics.CreateErr)
			return
		}
		intf := p.cfg.Intfs.Get(egIfid)
		if intf == nil {
			log.Error("[Propagator] Interface removed", "egIfid", egIfid)
			p.metrics.IncTotalBeacons(bseg.Segment.FirstIA(), bseg.InIfId, egIfid,
				metrics.CreateErr)
			return
		}
		topoInfo := intf.TopoInfo()
		ov := topoInfo.InternalAddrs.PublicOverlay(topoInfo.InternalAddrs.Overlay)

		err := p.beaconSender.Send(
			ctx,
			&seg.Beacon{Segment: bseg.Segment},
			topoInfo.ISD_AS,
			egIfid,
			p.cfg.Signer,
			ov,
		)
		if err != nil {
			log.Error("[Propagator] Unable to send packet", "egIfid", egIfid, "err", err)
			p.metrics.IncTotalBeacons(bseg.Segment.FirstIA(), bseg.InIfId, egIfid, metrics.SendErr)
			return
		}
		p.onSuccess(intf, egIfid)
	}()
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *beaconPropagator) shouldIgnore(bseg beacon.Beacon, egIfid common.IFIDType) bool {
	intf := p.cfg.Intfs.Get(egIfid)
	if intf == nil {
		return true
	}
	if err := beacon.FilterLoop(bseg, intf.TopoInfo().ISD_AS, p.allowIsdLoop); err != nil {
		log.Trace("[Propagator] Ignoring beacon on loop", "ifid", egIfid, "err", err)
		return true
	}
	return false
}

func (p *beaconPropagator) onSuccess(intf *ifstate.Interface, egIfid common.IFIDType) {
	intf.Propagate(p.tick.now)
	p.success.Inc()
	p.summary.AddIfid(egIfid)
	p.metrics.IncTotalBeacons(p.beacon.Segment.FirstIA(), p.beacon.InIfId, egIfid, metrics.Success)
}
