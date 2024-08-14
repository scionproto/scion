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
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/private/topology"
)

const (
	// defaultNewSenderTimeout is the default timeout to create a new beacon
	// sender.
	defaultNewSenderTimeout time.Duration = 5 * time.Second
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
	if err := p.run(ctx); err != nil {
		withSilent(ctx, p.Tick.Passed()).Error("Unable to propagate beacons", "err", err)
	}
	p.Tick.UpdateLast()
}

func (p *Propagator) run(ctx context.Context) error {
	intfs := p.needsBeacons()
	if len(intfs) == 0 {
		return nil
	}
	peers := sortedIntfs(p.AllInterfaces, topology.Peer)

	beacons, err := p.beaconsPerInterface(ctx, intfs)
	if err != nil {
		metrics.CounterInc(p.InternalErrors)
		return err
	}

	// Only log on info and error level every propagation period to reduce
	// noise. The offending logs events are redirected to debug level.
	silent := !p.Tick.Passed()
	logger := withSilent(ctx, silent)

	p.logCandidateBeacons(logger, beacons)

	var wg sync.WaitGroup
	for intf, beacons := range beacons {
		if len(beacons) == 0 {
			continue
		}
		wg.Add(1)
		intf := intf
		beacons := beacons
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			p := propagator{
				extender:      p.Extender,
				senderFactory: p.SenderFactory,
				propagated:    p.Propagated,
				now:           p.Tick.Now(),
				silent:        silent,
				intf:          intf,
				beacons:       beacons,
				peers:         peers,
			}
			if err := p.Propagate(ctx); err != nil {
				logger.Info("Error propagating beacons on interface",
					"egress_interface", intf.TopoInfo().ID,
					"err", err,
				)
			}
		}()
	}
	wg.Wait()
	return nil
}

// needsBeacons returns a list of active interfaces that beacons should be
// propagated on. In a core AS, these are all active core links. In a non-core
// AS, these are all active child links.
func (p *Propagator) needsBeacons() []*ifstate.Interface {
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

func (p *Propagator) beaconsPerInterface(
	ctx context.Context,
	intfs []*ifstate.Interface,
) (map[*ifstate.Interface][]beacon.Beacon, error) {

	allBeacons, err := p.Provider.BeaconsToPropagate(ctx)
	if err != nil {
		return nil, serrors.Wrap("fetching beacons to propagate", err)
	}
	var beacons []beacon.Beacon
	for _, b := range allBeacons {
		if p.AllInterfaces.Get(b.InIfID) == nil {
			continue
		}
		beacons = append(beacons, b)
	}
	r := make(map[*ifstate.Interface][]beacon.Beacon)
	for _, intf := range intfs {
		toPropagate := make([]beacon.Beacon, 0, len(beacons))
		for _, b := range beacons {
			if p.shouldIgnore(b, intf) {
				continue
			}
			ps, err := seg.BeaconFromPB(seg.PathSegmentToPB(b.Segment))
			if err != nil {
				return nil, err
			}
			toPropagate = append(toPropagate, beacon.Beacon{Segment: ps, InIfID: b.InIfID})
		}
		r[intf] = toPropagate
	}
	return r, nil
}

// shouldIgnore indicates whether a beacon should not be sent on the egress
// interface because it creates a loop.
func (p *Propagator) shouldIgnore(bseg beacon.Beacon, intf *ifstate.Interface) bool {
	if err := beacon.FilterLoop(bseg, intf.TopoInfo().IA, p.AllowIsdLoop); err != nil {
		return true
	}
	return false
}

// logCandidateBeacons logs the beacons that are candidates for beacon
// propagation.
func (p *Propagator) logCandidateBeacons(
	logger log.Logger,
	beaconsPerInterface map[*ifstate.Interface][]beacon.Beacon,
) {

	if !logger.Enabled(log.DebugLevel) {
		return
	}

	type Beacon struct {
		ID      string `json:"candidate_id"`
		Ingress uint16 `json:"ingress_interface"`
		Segment string `json:"segment"`
	}
	candidates := make(map[uint16][]Beacon, len(beaconsPerInterface))
	for intf, beacons := range beaconsPerInterface {
		infos := make([]Beacon, 0, len(beacons))
		for _, b := range beacons {
			infos = append(infos, Beacon{
				ID:      b.Segment.GetLoggingID(),
				Ingress: b.InIfID,
				Segment: hopsDescription(b.Segment.ASEntries),
			})
		}
		candidates[intf.TopoInfo().ID] = infos
	}
	logger.Debug("Candidate beacons for propagation", "candidates", candidates)
}

// propagator propagates a set of beacons on all active interfaces.
type propagator struct {
	extender      Extender
	senderFactory SenderFactory
	propagated    metrics.Counter

	now     time.Time
	silent  bool
	beacons []beacon.Beacon
	peers   []uint16
	intf    *ifstate.Interface
}

func (p *propagator) Propagate(ctx context.Context) error {
	var (
		logger   = withSilent(ctx, p.silent)
		topoInfo = p.intf.TopoInfo()
		egress   = topoInfo.ID

		mtx        sync.Mutex
		success    bool
		setSuccess = func() {
			mtx.Lock()
			defer mtx.Unlock()
			success = true
		}
	)

	senderStart := time.Now()
	senderCtx, cancel := context.WithTimeout(ctx, defaultNewSenderTimeout)
	defer cancel()
	sender, err := p.senderFactory.NewSender(
		senderCtx,
		topoInfo.IA,
		egress,
		net.UDPAddrFromAddrPort(topoInfo.InternalAddr),
	)
	if err != nil {
		for _, b := range p.beacons {
			p.incMetric(b.Segment.FirstIA(), b.InIfID, egress, prom.ErrNetwork)
		}
		return serrors.Wrap("getting beacon sender", err,
			"waited_for", time.Since(senderStart).String())

	}
	defer sender.Close()

	var wg sync.WaitGroup
	for _, b := range p.beacons {
		wg.Add(1)
		b := b
		go func() {
			defer log.HandlePanic()
			defer wg.Done()

			// Collect the ID before the segment is extended such that it
			// matches the ID that was logged above in logCandidateBeacons.
			id := b.Segment.GetLoggingID()

			if err := p.extender.Extend(ctx, b.Segment, b.InIfID, egress, p.peers); err != nil {
				logger.Error("Unable to extend beacon",
					"egress_interface", egress,
					"beacon.id", id,
					"beacon.ingress_interface", b.InIfID,
					"beacon.segment", hopsDescription(b.Segment.ASEntries),
					"err", err,
				)
				p.incMetric(b.Segment.FirstIA(), b.InIfID, egress, "err_create")
				return
			}

			sendStart := time.Now()
			if err := sender.Send(ctx, b.Segment); err != nil {
				logger.Info("Unable to send beacon",
					"egress_interface", egress,
					"beacon.id", id,
					"beacon.ingress_interface", b.InIfID,
					"beacon.segment", hopsDescription(b.Segment.ASEntries),
					"waited_for", time.Since(sendStart).String(),
					"err", err,
				)
				p.incMetric(b.Segment.FirstIA(), b.InIfID, egress, prom.ErrNetwork)
				return
			}

			setSuccess()
			p.incMetric(b.Segment.FirstIA(), b.InIfID, egress, prom.Success)
			p.intf.Propagate(p.now)

			if logger.Enabled(log.DebugLevel) {
				logger.Debug("Propagated beacon",
					"egress_interface", egress,
					"candidate_id", id,
					"beacon.ingress_interface", b.InIfID,
					"beacon.segment", hopsDescription(b.Segment.ASEntries),
					"waited_for", time.Since(sendStart).String(),
					"err", err,
				)
			}
		}()
	}
	wg.Wait()
	if !success {
		return serrors.New("no beacons propagated")
	}
	return nil
}

func (p *propagator) incMetric(startIA addr.IA, ingress, egress uint16, result string) {
	if p.propagated == nil {
		return
	}
	p.propagated.With(
		"start_isd_as", startIA.String(),
		"ingress_interface", strconv.Itoa(int(ingress)),
		"egress_interface", strconv.Itoa(int(egress)),
		prom.LabelResult, result,
	).Add(1)
}
