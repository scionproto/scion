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
	"sync"
	"time"

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

// DefaultRevOverlap specifies the default for how long before the expiry of an existing revocation
// the revoker can reissue a new revocation.
const DefaultRevOverlap = path_mgmt.MinRevTTL / 2

// TopoProvider provides a topology that is up to date.
type TopoProvider interface {
	Get() *topology.Topo
}

// RevConfig configures the revoker.
type RevConfig struct {
	RevOverlap time.Duration
}

// InitDefaults initializes the config fields that are not set to the default values.
func (c *RevConfig) InitDefaults() {
	if c.RevOverlap == 0 {
		c.RevOverlap = DefaultRevOverlap
	}
}

var _ periodic.Task = (*Revoker)(nil)

// Revoker issues revocations for interfaces that have timed out.
// Revocations for already revoked interfaces are renewed periodically.
type Revoker struct {
	intfs        *Interfaces
	msger        infra.Messenger
	cfg          RevConfig
	signer       infra.Signer
	topoProvider TopoProvider
}

// NewRevoker creates a new revoker from the given arguments.
func NewRevoker(intfs *Interfaces, msger infra.Messenger,
	signer infra.Signer, cfg RevConfig, topoProvider TopoProvider) *Revoker {

	cfg.InitDefaults()
	return &Revoker{
		intfs:        intfs,
		msger:        msger,
		cfg:          cfg,
		signer:       signer,
		topoProvider: topoProvider,
	}
}

// Run issues revocations for interfaces that have timed out
// and renews revocations for revoked interfaces.
func (r *Revoker) Run(ctx context.Context) {
	revs := make(map[common.IFIDType]*path_mgmt.SignedRevInfo)
	for ifid, intf := range r.intfs.All() {
		if intf.Expire() && !r.hasValidRevocation(intf) {
			if intf.Revocation() == nil {
				log.Info("[Revoker] interface went down", "ifid", ifid)
			}
			srev, err := r.createSignedRev(ifid)
			if err != nil {
				log.Error("[Revoker] Failed to create revocation", "ifid", ifid, "err", err)
				continue
			}
			if err := intf.Revoke(srev); err == nil {
				revs[ifid] = srev
			} else {
				log.Error("[Revoker] Failed to revoke!", "ifid", ifid, "err", err)
			}
		}
	}
	if len(revs) > 0 {
		wg := &sync.WaitGroup{}
		r.pushRevocationsToBRs(ctx, revs, wg)
		r.pushRevocationsToPS(ctx, revs)
		wg.Wait()
	}
}

func (r *Revoker) hasValidRevocation(intf *Interface) bool {
	if srev := intf.Revocation(); srev != nil {
		rev, err := srev.RevInfo()
		return err == nil && rev.RelativeTTL(time.Now()) >= r.cfg.RevOverlap
	}
	return false
}

func (r *Revoker) createSignedRev(ifid common.IFIDType) (*path_mgmt.SignedRevInfo, error) {
	now := util.TimeToSecs(time.Now())
	revInfo := &path_mgmt.RevInfo{
		IfID:         ifid,
		RawIsdas:     r.topoProvider.Get().ISD_AS.IAInt(),
		LinkType:     r.topoProvider.Get().IFInfoMap[ifid].LinkType,
		RawTimestamp: now,
		RawTTL:       uint32(path_mgmt.MinRevTTL.Seconds()),
	}
	rawRevInfo, err := revInfo.Pack()
	if err != nil {
		return nil, err
	}
	sign, err := r.signer.Sign(rawRevInfo)
	if err != nil {
		return nil, err
	}
	return path_mgmt.NewSignedRevInfo(revInfo, sign)
}

func (r *Revoker) pushRevocationsToBRs(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo, wg *sync.WaitGroup) {

	topo := r.topoProvider.Get()
	msg := &path_mgmt.IFStateInfos{
		Infos: make([]*path_mgmt.IFStateInfo, 0, len(revs)),
	}
	for ifid := range revs {
		msg.Infos = append(msg.Infos, infoFromInterface(ifid, r.intfs.Get(ifid)))
	}
	for brId, br := range topo.BR {
		r.sendToBr(ctx, brId, br, msg, wg)
	}
}

func (r *Revoker) sendToBr(ctx context.Context, brId string, br topology.BRInfo,
	msg *path_mgmt.IFStateInfos, wg *sync.WaitGroup) {

	wg.Add(1)
	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()

		topo := r.topoProvider.Get()
		a := &snet.Addr{
			IA:      topo.ISD_AS,
			Host:    br.CtrlAddrs.PublicAddr(topo.Overlay),
			NextHop: br.CtrlAddrs.OverlayAddr(topo.Overlay),
		}
		if err := r.msger.SendIfStateInfos(ctx, msg, a, messenger.NextId()); err != nil {
			log.Error("[Revoker] Failed to send revocations to BR", "br", brId, "err", err)
		}
	}()
}

func (r *Revoker) pushRevocationsToPS(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo) {

	topo := r.topoProvider.Get()
	svcInfo, err := topo.GetSvcInfo(proto.ServiceType_ps)
	if err != nil {
		log.Error("[Revoker] Failed to get svcInfo for PS", "err", err)
		return
	}
	topoAddr := svcInfo.GetAnyTopoAddr()
	if topoAddr == nil {
		log.Error("[Revoker] No PS found in topology")
		return
	}
	a := &snet.Addr{
		IA:      topo.ISD_AS,
		Host:    topoAddr.PublicAddr(topo.Overlay),
		NextHop: topoAddr.OverlayAddr(topo.Overlay),
	}
	for ifid, srev := range revs {
		if err := r.msger.SendRev(ctx, srev, a, messenger.NextId()); err != nil {
			log.Error("[Revoker] Failed to send revocation to PS", "ifid", ifid, "err", err)
		}
	}
}
