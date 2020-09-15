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

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

// BeaconProvider provides beacons to send to neighboring ASes.
type BeaconProvider interface {
	BeaconsToPropagate(ctx context.Context) (<-chan beacon.BeaconOrErr, error)
}

var _ periodic.Task = (*Propagator)(nil)

// Propagator forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	Extender     Extender
	BeaconSender BeaconSender
	Provider     BeaconProvider
	IA           addr.IA
	Signer       seg.Signer
	Intfs        *ifstate.Interfaces
	Core         bool
	AllowIsdLoop bool

	// tick is mutable.
	Tick Tick
}

// Name returns the tasks name.
func (p *Propagator) Name() string {
	return "bs_beaconing_propagator"
}

// Run propagates beacons provided by the beacon provider on all active target
// interfaces. In a core beacon server, core interfaces are the target
// interfaces. In a non-core beacon server, child interfaces are the target
// interfaces.
func (p *Propagator) Run(ctx context.Context) {
	p.Tick.now = time.Now()
	if err := p.run(ctx); err != nil {
		log.FromCtx(ctx).Error("Unable to propagate beacons", "err", err)
	}
	p.Tick.updateLast()
	metrics.Propagator.Runtime().Add(time.Since(p.Tick.now).Seconds())
}

func (p *Propagator) run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	intfs := p.needsBeacons(logger)
	if len(intfs) == 0 {
		return nil
	}
	peers, nonActivePeers := sortedIntfs(p.Intfs, topology.Peer)
	if len(nonActivePeers) > 0 && p.Tick.passed() {
		logger.Debug("Ignore non-active peering interfaces", "ifids", nonActivePeers)
	}
	beacons, err := p.Provider.BeaconsToPropagate(ctx)
	if err != nil {
		metrics.Propagator.InternalErrors().Inc()
		return err
	}
	s := newSummary()
	var wg sync.WaitGroup
	for bOrErr := range beacons {
		if bOrErr.Err != nil {
			logger.Error("Unable to get beacon", "err", bOrErr.Err)
			metrics.Propagator.InternalErrors().Inc()
			continue
		}
		if !intfActive(p.Intfs, bOrErr.Beacon.InIfId) {
			continue
		}
		b := beaconPropagator{
			Propagator:  p,
			beacon:      bOrErr.Beacon,
			activeIntfs: intfs,
			peers:       peers,
			summary:     s,
			logger:      logger,
		}
		b.start(ctx, &wg)
	}
	wg.Wait()
	p.logSummary(logger, s)
	return nil
}

// needsBeacons returns a list of active interface ids that beacons should be
// propagated to. In a core AS, these are all active core links. In a non-core
// AS, these are all active child links.
func (p *Propagator) needsBeacons(logger log.Logger) []common.IFIDType {
	var activeIntfs, nonActiveIntfs []common.IFIDType
	if p.Core {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.Intfs, topology.Core)
	} else {
		activeIntfs, nonActiveIntfs = sortedIntfs(p.Intfs, topology.Child)
	}
	if len(nonActiveIntfs) > 0 && p.Tick.passed() {
		logger.Debug("Ignore non-active interfaces", "ifids", nonActiveIntfs)
	}
	if p.Tick.passed() {
		return activeIntfs
	}
	stale := make([]common.IFIDType, 0, len(activeIntfs))
	for _, ifid := range activeIntfs {
		intf := p.Intfs.Get(ifid)
		if intf == nil {
			continue
		}
		if p.Tick.now.Sub(intf.LastPropagate()) > p.Tick.period {
			stale = append(stale, ifid)
		}
	}
	return stale
}

func (p *Propagator) logSummary(logger log.Logger, s *summary) {
	if p.Tick.passed() {
		logger.Info("Propagated beacons",
			"count", s.count, "startIAs", len(s.srcs), "egIfIds", s.IfIds())
		return
	}
	if s.count > 0 {
		logger.Info("Propagated beacons on stale interfaces",
			"count", s.count, "startIAs", len(s.srcs), "egIfIds", s.IfIds())
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
	logger      log.Logger
}

// start adds to the wait group and starts propagation of the beacon on
// all active interfaces.
func (p *beaconPropagator) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		if err := p.propagate(ctx); err != nil {
			p.logger.Error("Unable to propagate", "beacon", p.beacon, "err", err)
			return
		}
	}()
}

func (p *beaconPropagator) propagate(ctx context.Context) error {
	pb := seg.PathSegmentToPB(p.beacon.Segment)
	var expected int
	for _, egIfid := range p.activeIntfs {
		if p.shouldIgnore(p.beacon, egIfid) {
			continue
		}
		expected++
		// Create a "copy" from the original beacon to avoid races on the
		// ASEntry slice.
		ps, err := seg.BeaconFromPB(pb)
		if err != nil {
			metrics.Propagator.InternalErrors().Inc()
			return common.NewBasicError("Unable to unpack beacon", err)
		}
		p.extendAndSend(ctx, beacon.Beacon{Segment: ps, InIfId: p.beacon.InIfId}, egIfid)
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
	p.logger.Debug("Successfully propagated", "beacon", p.beacon,
		"expected", expected, "count", p.success.c)
	return nil
}

// extendAndSend extends the path segment with the AS entry and sends it on the
// egress interface, all done in a goroutine to avoid head-of-line blocking.
func (p *beaconPropagator) extendAndSend(ctx context.Context, bseg beacon.Beacon,
	egIfid common.IFIDType) {

	p.wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer p.wg.Done()

		labels := metrics.PropagatorLabels{
			StartIA: bseg.Segment.FirstIA(),
			InIfID:  bseg.InIfId,
			EgIfID:  egIfid,
		}
		now := time.Now()
		defer func() {
			// This captures the labels variable such that it can be modified in the code below.
			metrics.Propagator.IntfTime(labels).Add(time.Since(now).Seconds())
		}()

		if err := p.Extender.Extend(ctx, bseg.Segment, bseg.InIfId, egIfid, p.peers); err != nil {
			p.logger.Error("Unable to extend beacon", "beacon", bseg, "err", err)
			labels.Result = metrics.ErrCreate
			metrics.Propagator.Beacons(labels).Inc()
			return
		}
		intf := p.Intfs.Get(egIfid)
		if intf == nil {
			p.logger.Error("Interface removed", "egIfid", egIfid)
			labels.Result = metrics.ErrCreate
			metrics.Propagator.Beacons(labels).Inc()
			return
		}
		topoInfo := intf.TopoInfo()
		err := p.BeaconSender.Send(
			ctx,
			bseg.Segment,
			topoInfo.IA,
			egIfid,
			topoInfo.InternalAddr,
		)
		if err != nil {
			p.logger.Info("Unable to send packet", "egIfid", egIfid, "err", err)
			labels.Result = metrics.ErrSend
			metrics.Propagator.Beacons(labels).Inc()
			return
		}
		p.onSuccess(intf, egIfid)
		labels.Result = metrics.Success
		metrics.Propagator.Beacons(labels).Inc()
	}()
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *beaconPropagator) shouldIgnore(bseg beacon.Beacon, egIfid common.IFIDType) bool {
	intf := p.Intfs.Get(egIfid)
	if intf == nil {
		return true
	}
	if err := beacon.FilterLoop(bseg, intf.TopoInfo().IA, p.AllowIsdLoop); err != nil {
		p.logger.Debug("Ignoring beacon on loop", "ifid", egIfid, "err", err)
		return true
	}
	return false
}

func (p *beaconPropagator) onSuccess(intf *ifstate.Interface, egIfid common.IFIDType) {
	intf.Propagate(p.Tick.now)
	p.success.Inc()
	p.summary.AddIfid(egIfid)
}
