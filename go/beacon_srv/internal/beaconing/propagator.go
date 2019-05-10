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
	Sender         *onehop.Sender
	Period         time.Duration
	Core           bool
	AllowIsdLoop   bool
}

// Propagator forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	*segExtender
	sender       *onehop.Sender
	provider     BeaconProvider
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
		sender:       cfg.Sender,
		core:         cfg.Core,
		allowIsdLoop: cfg.AllowIsdLoop,
		segExtender:  extender,
		tick:         tick{period: cfg.Period},
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
}

func (p *Propagator) run(ctx context.Context) error {
	intfs := p.needsBeacons()
	if len(intfs) == 0 {
		return nil
	}
	peers, nonActivePeers := sortedIntfs(p.cfg.Intfs, proto.LinkType_peer)
	if len(nonActivePeers) > 0 && p.tick.passed() {
		log.Debug("[Propagator] Ignore inactive peer links", "ifids", nonActivePeers)
	}
	beacons, err := p.provider.BeaconsToPropagate(ctx)
	if err != nil {
		return err
	}
	wg := &sync.WaitGroup{}
	for bOrErr := range beacons {
		if bOrErr.Err != nil {
			log.Error("[Propagator] Unable to get beacon", "err", err)
			continue
		}
		p.startPropagate(bOrErr.Beacon, intfs, peers, wg)
	}
	wg.Wait()
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
		log.Debug("[Propagator] Ignore inactive links", "ifids", nonActiveIntfs)
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

// startPropagate adds to the wait group and starts propagation of the beacon on
// all active interfaces.
func (p *Propagator) startPropagate(origBeacon beacon.Beacon, activeIntfs,
	peers []common.IFIDType, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.propagate(origBeacon, activeIntfs, peers); err != nil {
			log.Error("[Propagator] Unable to propagate", "beacon", origBeacon, "err", err)
			return
		}
	}()
}

func (p *Propagator) propagate(origBeacon beacon.Beacon, activeIntfs,
	peers []common.IFIDType) error {

	raw, err := origBeacon.Segment.Pack()
	if err != nil {
		return err
	}
	var success ctr
	var expected int
	wg := sync.WaitGroup{}
	for _, egIfid := range activeIntfs {
		if p.shouldIgnore(origBeacon, egIfid) {
			continue
		}
		expected++
		bseg := origBeacon
		if bseg.Segment, err = seg.NewBeaconFromRaw(raw); err != nil {
			return common.NewBasicError("Unable to unpack beacon", err)
		}
		p.extendAndSend(bseg, egIfid, peers, &success, &wg)
	}
	wg.Wait()
	if success.c <= 0 && expected > 0 {
		return common.NewBasicError("None propagated", nil, "expected", expected)
	}
	log.Trace("[Propagator] Successfully propagated", "beacon", origBeacon,
		"expected", expected, "count", success.c)
	return nil
}

// extendAndSend extends the path segment with the AS entry and sends it on the
// egress interface, all done in a goroutine to avoid head-of-line blocking.
func (p *Propagator) extendAndSend(bseg beacon.Beacon, egIfid common.IFIDType,
	peers []common.IFIDType, success *ctr, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := p.extend(bseg.Segment, bseg.InIfId, egIfid, peers); err != nil {
			log.Error("[Propagator] Unable to extend beacon", "beacon", bseg, "err", err)
			return
		}
		intf := p.cfg.Intfs.Get(egIfid)
		if intf == nil {
			log.Error("[Propagator] Interface removed", "egIfid", egIfid)
		}
		topoInfo := intf.TopoInfo()
		msg, err := packBeaconMsg(&seg.Beacon{Segment: bseg.Segment}, topoInfo.ISD_AS,
			egIfid, p.cfg.Signer)
		if err != nil {
			log.Error("[Propagator] Unable pack message", "beacon", bseg, "err", err)
			return
		}
		ov := topoInfo.InternalAddrs.PublicOverlay(topoInfo.InternalAddrs.Overlay)
		if err := p.sender.Send(msg, ov); err != nil {
			log.Error("[Propagator] Unable to send packet", "ifid", "err", err)
			return
		}
		intf.Propagate(p.tick.now)
		success.Inc()
	}()
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *Propagator) shouldIgnore(bseg beacon.Beacon, egIfid common.IFIDType) bool {
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
