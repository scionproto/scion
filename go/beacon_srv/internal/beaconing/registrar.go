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

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
		<-chan beacon.BeaconOrErr, error)
}

var _ periodic.Task = (*Registrar)(nil)

// RegistrarConf is the configuration to create a new registrar.
type RegistrarConf struct {
	Config       ExtenderConf
	SegProvider  SegmentProvider
	TopoProvider topology.Provider
	Msgr         infra.Messenger
	Period       time.Duration
	SegType      proto.PathSegType
}

// Registrar is used to periodically register path segments with the appropriate
// path servers. Core and Up segments are registered with the local path server.
// Down segments are registered at the core.
type Registrar struct {
	*segExtender
	msgr         infra.Messenger
	segProvider  SegmentProvider
	topoProvider topology.Provider
	segType      proto.PathSegType

	// mutable fields
	lastSucc time.Time
	tick     tick
}

// New creates a new segment regsitration task.
func (cfg RegistrarConf) New() (*Registrar, error) {
	cfg.Config.task = "registrar"
	extender, err := cfg.Config.new()
	if err != nil {
		return nil, err
	}
	r := &Registrar{
		segProvider:  cfg.SegProvider,
		topoProvider: cfg.TopoProvider,
		segType:      cfg.SegType,
		msgr:         cfg.Msgr,
		tick:         tick{period: cfg.Period},
		segExtender:  extender,
	}
	return r, nil
}

// Run registers path segments for the specified type to path servers.
func (r *Registrar) Run(ctx context.Context) {
	r.tick.now = time.Now()
	if err := r.run(ctx); err != nil {
		log.Error("[Registrar] Unable to register", "type", r.segType, "err", err)
	}
	r.tick.updateLast()
}

func (r *Registrar) run(ctx context.Context) error {
	if r.tick.now.Sub(r.lastSucc) < r.tick.period {
		return nil
	}
	segments, err := r.segProvider.SegmentsToRegister(ctx, r.segType)
	if err != nil {
		return err
	}
	peers, nonActivePeers := sortedIntfs(r.cfg.Intfs, proto.LinkType_peer)
	if len(nonActivePeers) > 0 {
		log.Debug("[Registrar] Ignore non-active peer interfaces", "intfs", nonActivePeers)
	}
	var success, segErr, sendErr ctr
	wg := &sync.WaitGroup{}
	for bOrErr := range segments {
		reg, saddr, err := r.segToRegister(ctx, peers, bOrErr)
		if err != nil {
			log.Error("[Registrar] Unable to create segment", "type", r.segType, "err", err)
			segErr.Inc()
			continue
		}
		// Avoid head-of-line blocking when sending message to slow servers.
		r.startSendSegReg(ctx, reg, saddr, wg, &success, &sendErr)
	}
	wg.Wait()
	total := success.c + segErr.c + sendErr.c
	if success.c <= 0 {
		return common.NewBasicError("No beacons propagated", nil, "candidates", total,
			"segCreationErrs", segErr.c, "sendErrs", sendErr.c)
	}
	log.Info("[Registrar] Successfully registered segments", "success", success.c,
		"candidates", total, "segCreationErrs", segErr.c, "sendErrs", sendErr.c)
	r.lastSucc = r.tick.now
	return nil
}

// startSendSegReg adds to the wait group and starts a goroutine that sends the
// registration message to the peer.
func (r *Registrar) startSendSegReg(ctx context.Context, reg *path_mgmt.SegReg, saddr net.Addr,
	wg *sync.WaitGroup, success, sendErr *ctr) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		if err := r.msgr.SendSegReg(ctx, reg, saddr, messenger.NextId()); err != nil {
			log.Error("[Registrar] Unable to register segment", "addr", saddr, "err", err)
			sendErr.Inc()
			return
		}
		log.Debug("[Registrar] Successfully registered segment", "addr", saddr,
			"seg", reg.Recs[0].Segment)
		success.Inc()
	}()
}

func (r *Registrar) segToRegister(ctx context.Context, peers []common.IFIDType,
	bOrErr beacon.BeaconOrErr) (*path_mgmt.SegReg, net.Addr, error) {
	if bOrErr.Err != nil {
		return nil, nil, bOrErr.Err
	}
	pseg := bOrErr.Beacon.Segment
	if err := r.extend(pseg, bOrErr.Beacon.InIfId, 0, peers); err != nil {
		return nil, nil, common.NewBasicError("Unable to terminate", err, "beacon", bOrErr.Beacon)
	}
	reg := &path_mgmt.SegReg{
		SegRecs: &path_mgmt.SegRecs{
			Recs: []*seg.Meta{
				{
					Type:    r.segType,
					Segment: pseg,
				},
			},
		},
	}
	saddr, err := r.chooseServer(pseg)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to choose server", err)
	}
	return reg, saddr, nil
}

func (r *Registrar) chooseServer(pseg *seg.PathSegment) (net.Addr, error) {
	if r.segType != proto.PathSegType_down {
		topo := r.topoProvider.Get()
		return &snet.Addr{IA: topo.ISD_AS, Host: addr.NewSVCUDPAppAddr(addr.SvcPS)}, nil
	}
	return addrutil.GetPath(addr.SvcPS, pseg, r.topoProvider.Get())
}
