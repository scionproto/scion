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
	"time"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/cs/onehop"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

var _ periodic.Task = (*Originator)(nil)

// OriginatorConf is the configuration to create a new originator.
type OriginatorConf struct {
	Config       ExtenderConf
	BeaconSender *onehop.BeaconSender
	Period       time.Duration
}

// Originator originates beacons. It should only be used by core ASes.
type Originator struct {
	*segExtender
	beaconSender *onehop.BeaconSender

	// tick is mutable.
	tick tick
}

// New creates a new originator.
func (cfg OriginatorConf) New() (*Originator, error) {
	cfg.Config.task = "originator"
	extender, err := cfg.Config.new()
	if err != nil {
		return nil, err
	}
	o := &Originator{
		beaconSender: cfg.BeaconSender,
		segExtender:  extender,
		tick:         tick{period: cfg.Period},
	}
	return o, nil
}

// Name returns the tasks name.
func (o *Originator) Name() string {
	return "bs_beaconing_originator"
}

// Run originates core and downstream beacons.
func (o *Originator) Run(ctx context.Context) {
	o.tick.now = time.Now()
	o.originateBeacons(ctx, topology.Core)
	o.originateBeacons(ctx, topology.Child)
	metrics.Originator.Runtime().Add(time.Since(o.tick.now).Seconds())
	o.tick.updateLast()
}

// originateBeacons creates and sends a beacon for each active interface of
// the specified link type.
func (o *Originator) originateBeacons(ctx context.Context, linkType topology.LinkType) {
	logger := log.FromCtx(ctx)
	active, nonActive := sortedIntfs(o.cfg.Intfs, linkType)
	if len(nonActive) > 0 && o.tick.passed() {
		logger.Debug("[beaconing.Originator] Ignore non-active interfaces", "ifids", nonActive)
	}
	intfs := o.needBeacon(active)
	if len(intfs) == 0 {
		return
	}
	infoF := o.createInfoF(o.tick.now)
	s := newSummary()
	for _, ifid := range intfs {
		b := beaconOriginator{
			Originator: o,
			ifID:       ifid,
			infoF:      infoF,
			summary:    s,
		}
		if err := b.originateBeacon(ctx); err != nil {
			logger.Error("[beaconing.Originator] Unable to originate on interface",
				"ifid", ifid, "err", err)
		}
	}
	o.logSummary(logger, s, linkType)
}

// createInfoF creates the info field.
func (o *Originator) createInfoF(now time.Time) spath.InfoField {
	infoF := spath.InfoField{
		ConsDir: true,
		ISD:     uint16(o.beaconSender.IA.I),
		TsInt:   util.TimeToSecs(now),
	}
	return infoF
}

// needBeacon returns a list of interfaces that need a beacon.
func (o *Originator) needBeacon(active []common.IFIDType) []common.IFIDType {
	if o.tick.passed() {
		return active
	}
	stale := make([]common.IFIDType, 0, len(active))
	for _, ifid := range active {
		intf := o.cfg.Intfs.Get(ifid)
		if intf == nil {
			continue
		}
		if o.tick.now.Sub(intf.LastOriginate()) > o.tick.period {
			stale = append(stale, ifid)
		}
	}
	return stale
}

func (o *Originator) logSummary(logger log.Logger, s *summary, linkType topology.LinkType) {
	if o.tick.passed() {
		logger.Info("[beaconing.Originator] Originated beacons",
			"type", linkType.String(), "egIfIds", s.IfIds())
		return
	}
	if s.count > 0 {
		logger.Info("[beaconing.Originator] Originated beacons on stale interfaces",
			"type", linkType.String(), "egIfIds", s.IfIds())
	}
}

// beaconOriginator originates one beacon on the given interface.
type beaconOriginator struct {
	*Originator
	ifID    common.IFIDType
	infoF   spath.InfoField
	summary *summary
}

// originateBeacon originates a beacon on the given ifid.
func (o *beaconOriginator) originateBeacon(ctx context.Context) error {
	labels := metrics.OriginatorLabels{EgIfID: o.ifID, Result: metrics.Success}
	intf := o.cfg.Intfs.Get(o.ifID)
	if intf == nil {
		metrics.Originator.Beacons(labels.WithResult(metrics.ErrVerify)).Inc()
		return serrors.New("Interface does not exist")
	}
	topoInfo := intf.TopoInfo()
	bseg, err := o.createBeacon()
	if err != nil {
		metrics.Originator.Beacons(labels.WithResult(metrics.ErrCreate)).Inc()
		return common.NewBasicError("Unable to create beacon", err, "ifid", o.ifID)
	}

	err = o.beaconSender.Send(
		ctx,
		bseg,
		topoInfo.IA,
		o.ifID,
		o.cfg.Signer,
		topoInfo.InternalAddr,
	)
	if err != nil {
		metrics.Originator.Beacons(labels.WithResult(metrics.ErrSend)).Inc()
		return common.NewBasicError("Unable to send packet", err)
	}
	o.onSuccess(intf)
	metrics.Originator.Beacons(labels).Inc()
	return nil
}

func (o *beaconOriginator) createBeacon() (*seg.Beacon, error) {
	bseg, err := seg.NewSeg(&o.infoF)
	if err != nil {
		return nil, common.NewBasicError("Unable to create segment", err)
	}
	if err := o.extend(bseg, 0, o.ifID, nil); err != nil {
		return nil, common.NewBasicError("Unable to extend segment", err)
	}
	return &seg.Beacon{Segment: bseg}, nil
}

func (o *beaconOriginator) onSuccess(intf *ifstate.Interface) {
	intf.Originate(o.tick.now)
	o.summary.AddIfid(o.ifID)
	o.summary.Inc()
}
