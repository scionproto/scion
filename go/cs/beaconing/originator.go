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
	"crypto/rand"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

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

var _ periodic.Task = (*Originator)(nil)

// BeaconSender sends the beacon on the provided interface.
type BeaconSender interface {
	Send(ctx context.Context, beacon *seg.PathSegment, dst addr.IA,
		egress common.IFIDType, nextHop *net.UDPAddr) error
}

// Originator originates beacons. It should only be used by core ASes.
type Originator struct {
	Extender     Extender
	BeaconSender BeaconSender
	IA           addr.IA
	Signer       seg.Signer
	Intfs        *ifstate.Interfaces

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
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		o.originateBeacons(ctx, topology.Core)
	}()
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		o.originateBeacons(ctx, topology.Child)
	}()
	wg.Wait()
	o.Tick.UpdateLast()
}

// originateBeacons creates and sends a beacon for each active interface of
// the specified link type.
func (o *Originator) originateBeacons(ctx context.Context, linkType topology.LinkType) {
	logger := log.FromCtx(ctx)
	active := sortedIntfs(o.Intfs, linkType)
	intfs := o.needBeacon(active)
	if len(intfs) == 0 {
		return
	}
	s := newSummary()
	var wg sync.WaitGroup
	wg.Add(len(intfs))
	for _, ifid := range intfs {
		b := beaconOriginator{
			Originator: o,
			ifID:       ifid,
			timestamp:  o.Tick.Now(),
			summary:    s,
		}
		go func() {
			defer log.HandlePanic()
			defer wg.Done()

			if err := b.originateBeacon(ctx); err != nil {
				logger.Info("Unable to originate on interface",
					"egress_interface", b.ifID, "err", err)
			}
		}()
	}
	wg.Wait()
	o.logSummary(logger, s, linkType)
}

// needBeacon returns a list of interfaces that need a beacon.
func (o *Originator) needBeacon(active []common.IFIDType) []common.IFIDType {
	if o.Tick.Passed() {
		return active
	}
	stale := make([]common.IFIDType, 0, len(active))
	for _, ifid := range active {
		intf := o.Intfs.Get(ifid)
		if intf == nil {
			continue
		}
		if o.Tick.Overdue(intf.LastOriginate()) {
			stale = append(stale, ifid)
		}
	}
	return stale
}

func (o *Originator) logSummary(logger log.Logger, s *summary, linkType topology.LinkType) {
	if o.Tick.Passed() {
		logger.Debug("Originated beacons",
			"type", linkType.String(), "egress_interfaces", s.IfIds())
		return
	}
	if s.count > 0 {
		logger.Debug("Originated beacons on stale interfaces",
			"type", linkType.String(), "egress_interfaces", s.IfIds())
	}
}

// beaconOriginator originates one beacon on the given interface.
type beaconOriginator struct {
	*Originator
	ifID      common.IFIDType
	timestamp time.Time
	summary   *summary
}

// originateBeacon originates a beacon on the given ifid.
func (o *beaconOriginator) originateBeacon(ctx context.Context) error {
	labels := originatorLabels{Egress: o.ifID}
	intf := o.Intfs.Get(o.ifID)
	if intf == nil {
		o.incrementMetrics(labels.WithResult(prom.ErrValidate))
		return serrors.New("interface does not exist")
	}
	topoInfo := intf.TopoInfo()
	bseg, err := o.createBeacon(ctx)
	if err != nil {
		o.incrementMetrics(labels.WithResult("err_create"))
		return serrors.WrapStr("creating beacon", err, "egress_interface", o.ifID)
	}

	rpcContext, cancelF := context.WithTimeout(ctx, infra.DefaultRPCTimeout)
	defer cancelF()

	rpcStart := time.Now()
	err = o.BeaconSender.Send(
		rpcContext,
		bseg,
		topoInfo.IA,
		o.ifID,
		topoInfo.InternalAddr,
	)
	if err != nil {
		if rpcContext.Err() != nil {
			err = serrors.WrapStr("timed out waiting for RPC to complete", err,
				"waited_for", time.Since(rpcStart))
		}
		o.incrementMetrics(labels.WithResult(prom.ErrNetwork))
		return serrors.WrapStr("sending beacon", err)
	}
	o.onSuccess(intf)
	o.incrementMetrics(labels.WithResult(prom.Success))
	return nil
}

func (o *beaconOriginator) createBeacon(ctx context.Context) (*seg.PathSegment, error) {
	segID, err := rand.Int(rand.Reader, big.NewInt(1<<16))
	if err != nil {
		return nil, err
	}
	bseg, err := seg.CreateSegment(o.timestamp, uint16(segID.Uint64()))
	if err != nil {
		return nil, serrors.WrapStr("creating segment", err)
	}

	if err := o.Extender.Extend(ctx, bseg, 0, o.ifID, nil); err != nil {
		return nil, serrors.WrapStr("extending segment", err)
	}
	return bseg, nil
}

func (o *beaconOriginator) onSuccess(intf *ifstate.Interface) {
	intf.Originate(o.Tick.Now())
	o.summary.AddIfid(o.ifID)
	o.summary.Inc()
}

func (o *beaconOriginator) incrementMetrics(labels originatorLabels) {
	if o.Originator.Originated == nil {
		return
	}
	o.Originator.Originated.With(labels.Expand()...).Add(1)
}

type originatorLabels struct {
	Egress common.IFIDType
	Result string
}

func (l originatorLabels) Expand() []string {
	return []string{"egress_interface", strconv.Itoa(int(l.Egress)), prom.LabelResult, l.Result}
}

func (l originatorLabels) WithResult(result string) originatorLabels {
	l.Result = result
	return l
}
