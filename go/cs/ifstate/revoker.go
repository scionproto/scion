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

package ifstate

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// RevInserter stores revocation into persistent storage.
type RevInserter interface {
	InsertRevocations(ctx context.Context, revocations ...*path_mgmt.SignedRevInfo) error
}

// RevConfig configures the parameters for revocation creation.
type RevConfig struct {
	RevTTL     time.Duration
	RevOverlap time.Duration
}

// RevokerConf is the configuration to create a new revoker.
type RevokerConf struct {
	Intfs        *Interfaces
	Msgr         infra.Messenger
	Signer       infra.Signer
	TopoProvider topology.Provider
	RevInserter  RevInserter
	RevConfig    RevConfig
}

var _ periodic.Task = (*Revoker)(nil)

// Revoker issues revocations for interfaces that have timed out.
// Revocations for already revoked interfaces are renewed periodically.
type Revoker struct {
	cfg    RevokerConf
	pusher brPusher
}

// New creates a new revoker from the given arguments.
func (cfg RevokerConf) New() *Revoker {
	return &Revoker{
		cfg: cfg,
		pusher: brPusher{
			msgr: cfg.Msgr,
			mode: "revoker",
		},
	}
}

// Name returns the tasks name.
func (r *Revoker) Name() string {
	return "bs_ifstate_revoker"
}

// Run issues revocations for interfaces that have timed out
// and renews revocations for revoked interfaces.
func (r *Revoker) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	revs := make(map[common.IFIDType]*path_mgmt.SignedRevInfo)
	for ifid, intf := range r.cfg.Intfs.All() {
		labelsIssued := metrics.IssuedLabels{
			IfID:    ifid,
			NeighIA: intf.TopoInfo().IA,
			State:   metrics.RevRenew,
		}
		labelsDuration := metrics.DurationLabels{
			IfID:    ifid,
			NeighIA: intf.TopoInfo().IA,
		}

		if intf.Revoke() && !r.hasValidRevocation(intf) {
			if intf.Revocation() == nil {
				labelsIssued.State = metrics.RevNew
				logger.Info("[ifstate.Revoker] interface went down", "ifid", ifid)
			}
			srev, err := r.createSignedRev(ifid)
			if err != nil {
				logger.Error("[ifstate.Revoker] Failed to create revocation",
					"ifid", ifid, "err", err)
				continue
			}
			if err := intf.SetRevocation(srev); err != nil {
				logger.Error("[ifstate.Revoker] Failed to revoke!", "ifid", ifid, "err", err)
				continue
			}
			if rev, err := srev.RevInfo(); err != nil {
				metrics.Ifstate.Duration(labelsDuration).Add(float64(rev.RawTTL))
			}
			metrics.Ifstate.Issued(labelsIssued).Inc()
			revs[ifid] = srev
		}
	}
	if len(revs) > 0 {
		wg := &sync.WaitGroup{}
		if err := r.cfg.RevInserter.InsertRevocations(ctx, toSlice(revs)...); err != nil {
			logger.Error("[ifstate.Revoker] Failed to insert revocations in store", "err", err)
			// still continue to try to push it to BR/PS.
		}
		r.pushRevocationsToBRs(ctx, revs, wg)
		r.pushRevocationsToPS(ctx, revs)
		wg.Wait()
	}
}

func (r *Revoker) hasValidRevocation(intf *Interface) bool {
	if srev := intf.Revocation(); srev != nil {
		rev, err := srev.RevInfo()
		return err == nil && rev.RelativeTTL(time.Now()) >= r.cfg.RevConfig.RevOverlap
	}
	return false
}

func (r *Revoker) createSignedRev(ifid common.IFIDType) (*path_mgmt.SignedRevInfo, error) {
	now := util.TimeToSecs(time.Now())
	revInfo := &path_mgmt.RevInfo{
		IfID:         ifid,
		RawIsdas:     r.cfg.TopoProvider.Get().IA().IAInt(),
		LinkType:     proto.LinkType(r.cfg.TopoProvider.Get().IFInfoMap()[ifid].LinkType),
		RawTimestamp: now,
		RawTTL:       uint32(r.cfg.RevConfig.RevTTL.Seconds()),
	}
	return path_mgmt.NewSignedRevInfo(revInfo, r.cfg.Signer)
}

func (r *Revoker) pushRevocationsToBRs(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo, wg *sync.WaitGroup) {

	msg := &path_mgmt.IFStateInfos{
		Infos: make([]*path_mgmt.IFStateInfo, 0, len(revs)),
	}
	for ifid := range revs {
		msg.Infos = append(msg.Infos, infoFromInterface(ifid, r.cfg.Intfs.Get(ifid)))
	}

	l := metrics.SentLabels{Dst: metrics.DstBR}
	metrics.Ifstate.Sent(l).Add(float64(len(msg.Infos)))
	r.pusher.sendIfStateToAllBRs(ctx, msg, r.cfg.TopoProvider.Get(), wg)
}

func (r *Revoker) pushRevocationsToPS(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo) {

	topo := r.cfg.TopoProvider.Get()
	labels := metrics.SentLabels{Dst: metrics.DstPS}

	a := &snet.SVCAddr{IA: topo.IA(), SVC: addr.SvcPS}
	for ifid, srev := range revs {
		if err := r.cfg.Msgr.SendRev(ctx, srev, a, messenger.NextId()); err != nil {
			log.FromCtx(ctx).Error("[ifstate.Revoker] Failed to send revocation to PS",
				"ifid", ifid, "err", err)
		}
		metrics.Ifstate.Sent(labels).Inc()
	}
}

type brPusher struct {
	msgr infra.Messenger
	mode string
}

func (p *brPusher) sendIfStateToAllBRs(ctx context.Context, msg *path_mgmt.IFStateInfos,
	topo topology.Topology, wg *sync.WaitGroup) {

	for _, br := range topo.BRNames() {
		t := topo.SBRAddress(br)
		p.sendIfStateToBr(ctx, msg, br, t, wg)
	}
}

func (p *brPusher) sendIfStateToBr(ctx context.Context, msg *path_mgmt.IFStateInfos,
	id string, a net.Addr, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		if err := p.msgr.SendIfStateInfos(ctx, msg, a, messenger.NextId()); err != nil {
			log.FromCtx(ctx).Error("Failed to send interface state to BR",
				"br", id, "mode", p.mode, "err", err, "address", a)
		}
	}()
}

func toSlice(revs map[common.IFIDType]*path_mgmt.SignedRevInfo) []*path_mgmt.SignedRevInfo {
	res := make([]*path_mgmt.SignedRevInfo, 0, len(revs))
	for _, rev := range revs {
		res = append(res, rev)
	}
	return res
}
