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
	"hash"
	"net"
	"sort"
	"sync"

	"github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/proto"
)

// SegmentProvider provides segments to register for the specified type.
type SegmentProvider interface {
	SegmentsToRegister(ctx context.Context, segType proto.PathSegType) (
		<-chan beacon.BeaconOrErr, error)
}

var _ periodic.Task = (*Registrar)(nil)

// Registrar is used to periodically register path segments with the appropriate
// path servers. Core and Up segments are registered with the local path server.
// Down segments are registered at the core.
type Registrar struct {
	segExtender
	msgr     infra.Messenger
	provider SegmentProvider
	segType  proto.PathSegType
}

// NewRegistrar creates a new segment regsitration task.
func NewRegistrar(intfs *ifstate.Interfaces, segType proto.PathSegType, mac hash.Hash,
	provider SegmentProvider, msgr infra.Messenger, cfg Config) (*Registrar, error) {

	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	r := &Registrar{
		provider: provider,
		segType:  segType,
		msgr:     msgr,
		segExtender: segExtender{
			cfg:   cfg,
			mac:   mac,
			intfs: intfs,
			task:  "registrar",
		},
	}
	return r, nil
}

// Run registers path segments for the specified type to path servers.
func (r *Registrar) Run(ctx context.Context) {
	if err := r.run(ctx); err != nil {
		log.Error("[Registrar] Unable to register", "type", r.segType, "err", err)
	}
}

func (r *Registrar) run(ctx context.Context) error {
	segments, err := r.provider.SegmentsToRegister(ctx, r.segType)
	if err != nil {
		return err
	}
	peers := r.sortedActivePeers()
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

func (r *Registrar) sortedActivePeers() []common.IFIDType {
	var ifids []common.IFIDType
	for ifid, intf := range r.intfs.All() {
		if intf.TopoInfo().LinkType != proto.LinkType_peer {
			continue
		}
		if intf.State() != ifstate.Active {
			log.Debug("[Registrar] Ignore inactive peer link", "ifid", ifid)
			continue
		}
		ifids = append(ifids, ifid)
	}
	sort.Slice(ifids, func(i, j int) bool { return ifids[i] < ifids[j] })
	return ifids
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
		return r.localServer()
	}
	return addrutil.GetPath(addr.SvcPS, pseg, itopo.Get())
}

func (r *Registrar) localServer() (*snet.Addr, error) {
	topo := itopo.Get()
	ps, err := topo.PSNames.GetRandom()
	if err != nil {
		return nil, err
	}
	topoAddr := topo.PS[ps]
	saddr := &snet.Addr{
		IA:   topo.ISD_AS,
		Host: topoAddr.PublicAddr(topoAddr.Overlay),
	}
	return saddr, nil
}

type ctr struct {
	sync.Mutex
	c int
}

func (c *ctr) Inc() {
	c.Lock()
	defer c.Unlock()
	c.c++
}
