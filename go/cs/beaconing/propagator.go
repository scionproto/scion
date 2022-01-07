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
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
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
	ProvideBeacons(ctx context.Context) ([]beacon.Beacon, error)
}

var _ periodic.Task = (*Propagator)(nil)

// Propagator is the task that forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	Extender              Extender
	SenderFactory         SenderFactory
	Provider_             BeaconProvider
	Mechanism             BeaconingMechanism
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

// Represents a batch of beacons to propagate, stored in intf2bcns, where egress interfaces map to beacons
type PropagationBatch struct {
	*Propagator
	wg      sync.WaitGroup
	batch   SendableBeaconsBatch
	success ctr
}

type BeaconsToPropagate map[*ifstate.Interface][]beacon.Beacon

func (p *Propagator) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	p.Tick.SetNow(time.Now())
	if err := p.run(ctx); err != nil {
		logger.Error("Unable to propagate beacons", "err", err)
	}
	p.Tick.UpdateLast()
}

// Name returns the tasks name.
func (p *Propagator) Name() string {
	return "control_beaconing_propagator"
}

func (p *Propagator) run(ctx context.Context) error {
	batch_, err := p.Mechanism.ProvidePropagationBatch(ctx, p.Tick)
	if err != nil {
		return serrors.WrapStr("error creating propagation batch", err)
	}
	batch := PropagationBatch{
		Propagator: p,
		batch:      batch_,
	}

	if sendErr := batch.sendBeacons(ctx); sendErr != nil {
		return serrors.WrapStr("error propagating", sendErr, "intf -> bcns:", batch.batch)
	}
	return nil
}

// Sends beacons to their interfaces in intf2bcns map
func (p *PropagationBatch) sendBeacons(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	var expected int
	for egIntf, bcns := range p.batch {
		p.send(ctx, bcns, egIntf)
		p.wg.Add(1)
		expected++
	}
	p.wg.Wait()
	if expected == 0 {
		return nil
	}
	if p.success.c <= 0 {
		return serrors.New("no beacon propagated", "expected", expected)
	}
	logger.Debug("Successfully propagated", "beacons on interfaces", p.batch,
		"expected", expected, "count", p.success.c)
	return nil
}

// Sends a set of beacons to a given interface
func (p *PropagationBatch) send(ctx context.Context, bcns []beacon.Beacon, intf *ifstate.Interface) {
	logger := log.FromCtx(ctx)
	if len(bcns) == 0 {
		return
	}
	egIfid := intf.TopoInfo().ID

	go func() {
		defer log.HandlePanic()
		defer p.wg.Done()
		topoInfo := intf.TopoInfo()

		rpcContext, cancelF := context.WithTimeout(ctx, DefaultRPCTimeout)
		defer cancelF()

		rpcStart := time.Now()
		sender, err := p.SenderFactory.NewSender(rpcContext, topoInfo.IA, egIfid,
			topoInfo.InternalAddr.UDPAddr())
		if err != nil {
			if rpcContext.Err() != nil {
				err = serrors.WrapStr("timed out getting beacon sender", err,
					"waited_for", time.Since(rpcStart))
			}
			logger.Info("Unable to propagate beacons", "egress_interface", egIfid, "err", err)
			for _, b := range bcns {
				p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
			}
			return
		}
		defer sender.Close()

		successes := 0
		for _, b := range bcns {
			if err := sender.Send(rpcContext, b.Segment); err != nil {
				if rpcContext.Err() != nil {
					err = serrors.WrapStr("timed out waiting for RPC to complete", err,
						"waited_for", time.Since(rpcStart))
					logger.Info("Unable to propagate beacons", "egress_interface", egIfid,
						"err", err)
					p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
					// Return here if the context is expired, since no RPC will complete at that
					// point.
					return
				}
				logger.Info("Unable to propagate beacons", "egress_interface", egIfid, "err", err)
				p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.ErrNetwork)
				continue
			}
			logger.Debug("Propagated one beacon")
			p.onSuccess(intf, egIfid)
			p.incMetric(b.Segment.FirstIA(), b.InIfId, egIfid, prom.Success)
			successes++
		}
		logger.Debug("Propagated beacons", "egress_interface", egIfid, "expected",
			len(bcns), "successes", successes)
	}()
}

func (p *PropagationBatch) onSuccess(intf *ifstate.Interface, egIfid uint16) {
	intf.Propagate(p.Tick.Now())
	p.success.Inc()
}

func (p *PropagationBatch) incMetric(startIA addr.IA, ingress, egress uint16, result string) {
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
