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
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
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
	if err := p.run(ctx); err != nil {
		log.FromCtx(ctx).Error("Unable to propagate beacons", "err", err)
	}
	p.Tick.UpdateLast()
}

func (p *Propagator) run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	intfs := p.needsBeacons(logger)
	if len(intfs) == 0 {
		return nil
	}
	peers := sortedIntfs(p.Intfs, topology.Peer)
	beacons, err := p.Provider.BeaconsToPropagate(ctx)
	if err != nil {
		p.incrementInternalErrors()
		return err
	}
	s := newSummary()
	var wg sync.WaitGroup
	for bOrErr := range beacons {
		if bOrErr.Err != nil {
			logger.Error("Unable to get beacon", "err", bOrErr.Err)
			p.incrementInternalErrors()
			continue
		}
		if p.Intfs.Get(bOrErr.Beacon.InIfId) == nil {
			continue
		}
		b := beaconPropagator{
			Propagator: p,
			beacon:     bOrErr.Beacon,
			intfs:      intfs,
			peers:      peers,
			summary:    s,
			logger:     logger,
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
	var intfs []common.IFIDType
	if p.Core {
		intfs = sortedIntfs(p.Intfs, topology.Core)
	} else {
		intfs = sortedIntfs(p.Intfs, topology.Child)
	}
	if p.Tick.Passed() {
		return intfs
	}
	stale := make([]common.IFIDType, 0, len(intfs))
	for _, ifid := range intfs {
		intf := p.Intfs.Get(ifid)
		if intf == nil {
			continue
		}
		if p.Tick.Overdue(intf.LastPropagate()) {
			stale = append(stale, ifid)
		}
	}
	return stale
}

func (p *Propagator) logSummary(logger log.Logger, s *summary) {
	if p.Tick.Passed() {
		logger.Debug("Propagated beacons",
			"count", s.count, "start_isd_ases", len(s.srcs), "egress_interfaces", s.IfIds())
		return
	}
	if s.count > 0 {
		logger.Debug("Propagated beacons on stale interfaces",
			"count", s.count, "start_isd_ases", len(s.srcs), "egress_interfaces", s.IfIds())
	}
}

func (p *Propagator) incrementInternalErrors() {
	if p.InternalErrors == nil {
		return
	}
	p.InternalErrors.Add(1)
}

// beaconPropagator propagates one beacon to all active interfaces.
type beaconPropagator struct {
	*Propagator
	wg      sync.WaitGroup
	beacon  beacon.Beacon
	intfs   []common.IFIDType
	peers   []common.IFIDType
	success ctr
	summary *summary
	logger  log.Logger
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
	for _, egIfid := range p.intfs {
		if p.shouldIgnore(p.beacon, egIfid) {
			continue
		}
		expected++
		// Create a "copy" from the original beacon to avoid races on the
		// ASEntry slice.
		ps, err := seg.BeaconFromPB(pb)
		if err != nil {
			p.Propagator.incrementInternalErrors()
			return serrors.WrapStr("Unable to unpack beacon", err)
		}
		p.extendAndSend(ctx, beacon.Beacon{Segment: ps, InIfId: p.beacon.InIfId}, egIfid)
	}
	p.wg.Wait()
	if expected == 0 {
		return nil
	}
	if p.success.c <= 0 {
		return serrors.New("no beacon propagated", "expected", expected)
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

		labels := propagatorLabels{
			StartIA: bseg.Segment.FirstIA(),
			Ingress: bseg.InIfId,
			Egress:  egIfid,
		}

		if err := p.Extender.Extend(ctx, bseg.Segment, bseg.InIfId, egIfid, p.peers); err != nil {
			p.logger.Error("Unable to extend beacon", "beacon", bseg, "err", err)
			p.incrementMetrics(labels.WithResult("err_create"))
			return
		}
		intf := p.Intfs.Get(egIfid)
		if intf == nil {
			p.logger.Error("Interface removed", "egress_interface", egIfid)
			p.incrementMetrics(labels.WithResult(prom.ErrValidate))
			return
		}
		topoInfo := intf.TopoInfo()

		rpcContext, cancelF := context.WithTimeout(ctx, infra.DefaultRPCTimeout)
		defer cancelF()
		rpcStart := time.Now()

		err := p.BeaconSender.Send(
			rpcContext,
			bseg.Segment,
			topoInfo.IA,
			egIfid,
			topoInfo.InternalAddr,
		)
		if err != nil {
			if rpcContext.Err() != nil {
				err = serrors.WrapStr("timed out waiting for RPC to complete", err,
					"waited_for", time.Since(rpcStart))
			}
			p.logger.Info("Unable to send packet", "egress_interface", egIfid, "err", err)
			p.incrementMetrics(labels.WithResult(prom.ErrNetwork))
			return
		}
		p.onSuccess(intf, egIfid)
		p.incrementMetrics(labels.WithResult(prom.Success))
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
		p.logger.Debug("Ignoring beacon on loop", "egress_interface", egIfid, "err", err)
		return true
	}
	return false
}

func (p *beaconPropagator) onSuccess(intf *ifstate.Interface, egIfid common.IFIDType) {
	intf.Propagate(p.Tick.Now())
	p.success.Inc()
	p.summary.AddIfid(egIfid)
}

func (p *beaconPropagator) incrementMetrics(labels propagatorLabels) {
	if p.Propagator.Propagated == nil {
		return
	}
	p.Propagator.Propagated.With(labels.Expand()...).Add(1)
}

type propagatorLabels struct {
	StartIA addr.IA
	Egress  common.IFIDType
	Ingress common.IFIDType
	Result  string
}

func (l propagatorLabels) Expand() []string {
	return []string{
		"start_isd_as", l.StartIA.String(),
		"ingress_interface", strconv.Itoa(int(l.Ingress)),
		"egress_interface", strconv.Itoa(int(l.Egress)),
		prom.LabelResult, l.Result,
	}
}

func (l propagatorLabels) WithResult(result string) propagatorLabels {
	l.Result = result
	return l
}
