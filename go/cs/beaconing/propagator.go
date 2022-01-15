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

var _ periodic.Task = (*Propagator)(nil)

// Propagator is the task that forwards beacons to neighboring ASes. In a core AS, the beacons
// are propagated to neighbors on core links. In a non-core AS, the beacons are
// forwarded on child links. Selection of the beacons is handled by the beacon
// provider, the propagator only filters AS loops.
type Propagator struct {
	Extender              Extender
	SenderFactory         SenderFactory
	Mechanism             PropagationBeaconProvider
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
	batch, err := p.Mechanism.ProvidePropagationBatch(ctx, p.Tick)
	if err != nil {
		return serrors.WrapStr("error creating propagation batch", err)
	}

	if sendErr := p.sendBatch(ctx, batch); sendErr != nil {
		return serrors.WrapStr("error propagating", sendErr, "intf -> bcns:", batch)
	}
	return nil
}

// Sends beacons to their interfaces in intf2bcns map
func (p *Propagator) sendBatch(ctx context.Context, batch SendableBeaconsBatch) error {
	var expected int
	var wg sync.WaitGroup
	success := new(ctr)
	for egIntf, bcns := range batch {
		wg.Add(1)
		expected += len(bcns)

		go func(egIntf *ifstate.Interface, bcns []beacon.Beacon) {
			defer log.HandlePanic()
			defer wg.Done()
			p.send(ctx, bcns, egIntf, success)
		}(egIntf, bcns)
	}
	wg.Wait()

	if success.c <= 0 && expected > 0 {
		return serrors.New("no beacon propagated", "expected", expected)
	}
	return nil
}

// Sends a set of beacons to a given interface
func (p *Propagator) send(ctx context.Context, bcns []beacon.Beacon, intf *ifstate.Interface, success *ctr) {
	if len(bcns) == 0 {
		return
	}

	logger := log.FromCtx(ctx)

	// Prepare sender parameters
	timeout := DefaultRPCTimeout
	ia := intf.TopoInfo().IA
	egress := intf.TopoInfo().ID
	nexthop := intf.TopoInfo().InternalAddr.UDPAddr()

	// Create sender
	sender, err := p.SenderFactory.NewSender(ctx, timeout, ia, egress, nexthop)
	if err != nil {
		for _, b := range bcns {
			ingress := b.InIfId
			p.incMetric(b.Segment.FirstIA(), ingress, egress, prom.ErrNetwork)
		}
		return // serrors.WrapStr("error creating sender", err)
	}
	defer sender.Close()

	successes := 0
	// Send beacons using the created sender
	for _, bcn := range bcns {
		logger.Debug("Sending beacon ", "bcn", bcn.Segment.ASEntries[0].Extensions)
		if err := sender.Send(bcn.Segment); err != nil {
			p.incMetric(bcn.Segment.FirstIA(), bcn.InIfId, egress, prom.ErrNetwork)
			return // serrors.WrapStr("sending beacon", err)
		} else {
			logger.Debug("Propagated one beacon")
			p.incMetric(bcn.Segment.FirstIA(), bcn.InIfId, egress, prom.Success)
			intf.Propagate(p.Tick.Now())
			success.Inc()
			successes++

		}
	}
}
func (p *Propagator) incMetric(startIA addr.IA, ingress, egress uint16, result string) {
	if p.Propagated == nil {
		return
	}
	p.Propagated.With(
		"start_isd_as", startIA.String(),
		"ingress_interface", strconv.Itoa(int(ingress)),
		"egress_interface", strconv.Itoa(int(egress)),
		"propagator_IA", p.IA.String(),
		prom.LabelResult, result,
	).Add(1)
}
