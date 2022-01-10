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
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
)

type SenderFactoryNew interface {
	NewSender(
		parentCtx context.Context,
		contextTimeout time.Duration,
		dst addr.IA,
		egress uint16,
		nexthop *net.UDPAddr,
	) (SenderNew, error)
}

type SenderNew interface {
	Send(s *seg.PathSegment) error
	Close() error
}

// DEBUG

const (
	NEW_MECHANISM = true
)

// Originator originates beacons. It should only be used by core ASes.
type Originator struct {
	Extender              Extender
	SenderFactory         SenderFactory
	SenderFactoryNew      SenderFactoryNew
	Provider              OriginationBeaconProvider
	IA                    addr.IA
	Signer                seg.Signer
	AllInterfaces         *ifstate.Interfaces
	OriginationInterfaces func() []*ifstate.Interface

	Originated metrics.Counter

	// Tick is mutable.
	Tick Tick
}

// Name returns the tasks name.
func (o *Originator) Name() string {
	return "control_beaconing_originator"
}

// Run originates core and downstream beacons.
func (o *Originator) Run(ctx context.Context) {
	o.Tick.SetNow(time.Now())
	if NEW_MECHANISM {
		o.originateBeaconsNew(ctx)
	} else {
		o.originateBeacons(ctx)
	}
	o.Tick.UpdateLast()
}

func (o *Originator) originateBeaconsNew(ctx context.Context) {
	logger := log.FromCtx(ctx)

	batch, err := o.Provider.ProvideOriginationBatch(ctx, o.Tick)
	if err != nil {
		logger.Error("getting origination batch", "error", err)
	}
	// Used to wait for sending goroutings
	var wg sync.WaitGroup
	// Collects succesful interfaces & no. beacons sent
	s := newSummary()

	for intf, bcns := range batch {

		// Copy vars for closure, golang quirk
		intf := intf
		bcns := bcns

		// Start sending goroutine
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()

			if err := o.sendBeaconsNew(ctx, intf, bcns, s); err != nil {
				logger.Info("Unable to originate on interface",
					"egress_interface", intf.TopoInfo().ID, "err", err, "bcns", bcns)
			}
		}()
	}
	wg.Wait()
	o.logSummary(ctx, s)
}

func (o *Originator) sendBeaconsNew(
	ctx context.Context,
	intf *ifstate.Interface,
	bcns []beacon.Beacon,
	sum *summary) error {
	// Create labels for reporting
	labels := originatorLabels{intf: intf}

	// Prepare sender parameters
	timeout := DefaultRPCTimeout
	ia := intf.TopoInfo().IA
	egress := intf.TopoInfo().ID
	nexthop := intf.TopoInfo().InternalAddr.UDPAddr()

	// Create sender
	sender, err := o.SenderFactoryNew.NewSender(ctx, timeout, ia, egress, nexthop)
	if err != nil {
		o.incrementMetrics(labels.WithResult(prom.ErrNetwork))
		return serrors.WrapStr("error creating sender", err)
	}
	defer sender.Close()

	// Send each beacon using created sender
	for _, bcn := range bcns {
		if err := sender.Send(bcn.Segment); err != nil {
			o.incrementMetrics(labels.WithResult(prom.ErrNetwork))
			return serrors.WrapStr("sending beacon", err)
		} else {
			intf.Originate(o.Tick.Now())
			sum.AddIfid(intf.TopoInfo().ID)
			sum.Inc()
			o.incrementMetrics(labels.WithResult(prom.Success))
		}
	}

	return nil
}
