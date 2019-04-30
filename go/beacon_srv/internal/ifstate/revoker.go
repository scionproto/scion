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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// DefaultRevOverlap specifies the default for how long before the expiry of an existing revocation
// the revoker can reissue a new revocation.
const DefaultRevOverlap = path_mgmt.MinRevTTL / 2

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

// Revoker revokes interfaces for which we didn't receive an ifid keepalive message for too long.
type Revoker struct {
	intfs  *Interfaces
	msger  infra.Messenger
	cfg    RevConfig
	signer infra.Signer
}

func NewRevoker(intfs *Interfaces, msger infra.Messenger,
	signer infra.Signer, cfg RevConfig) *Revoker {

	cfg.InitDefaults()
	return &Revoker{
		intfs:  intfs,
		msger:  msger,
		cfg:    cfg,
		signer: signer,
	}
}

func (r *Revoker) Run(ctx context.Context) {
	if err := r.run(ctx); err != nil {
		log.Error("[Revoker] Failed to run revoker", "err", err)
	}
}

func (r *Revoker) run(ctx context.Context) error {
	var revIfIds []common.IFIDType
	for ifid, intf := range r.intfs.All() {
		if intf.Expire() {
			var existingRevInfo *path_mgmt.RevInfo
			if existingRev := intf.Revocation(); existingRev != nil {
				var err error
				existingRevInfo, err = existingRev.RevInfo()
				if err != nil {
					log.Warn("[Revoker] couldn't extract rev info from existing revocation",
						"err", err)
				}
			}
			if existingRevInfo == nil {
				log.Info("[Revoker] interface went down", "ifid", ifid)
			}
			if sendRevocation := existingRevInfo == nil ||
				existingRevInfo.RelativeTTL(time.Now()) < r.cfg.RevOverlap; sendRevocation {
				revIfIds = append(revIfIds, ifid)
			}
		}
	}
	if len(revIfIds) > 0 {
		revs := r.createRevocations(revIfIds)
		r.revokeInterfaces(revs)
		r.pushRevocationsToBRs(ctx, revs)
		r.pushRevocationsToPS(ctx, revs)
	}
	return nil
}

func (r *Revoker) createRevocations(
	ifids []common.IFIDType) map[common.IFIDType]*path_mgmt.SignedRevInfo {

	revs := make(map[common.IFIDType]*path_mgmt.SignedRevInfo)
	for _, ifid := range ifids {
		srev, err := r.signedRevInfo(ifid)
		if err != nil {
			log.Error("[Revoker] Failed to create revocation", "ifid", ifid, "err", err)
			continue
		}
		revs[ifid] = srev
	}
	return revs
}

func (r *Revoker) signedRevInfo(ifid common.IFIDType) (*path_mgmt.SignedRevInfo, error) {
	now := util.TimeToSecs(time.Now())
	revInfo := &path_mgmt.RevInfo{
		IfID:         ifid,
		RawIsdas:     itopo.Get().ISD_AS.IAInt(),
		LinkType:     itopo.Get().IFInfoMap[ifid].LinkType,
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

func (r *Revoker) revokeInterfaces(revs map[common.IFIDType]*path_mgmt.SignedRevInfo) {
	for ifid, srev := range revs {
		if intf := r.intfs.Get(ifid); intf != nil {
			if err := intf.Revoke(srev); err != nil {
				// interface activated in the meantime, so delete it from the map.
				delete(revs, ifid)
			}
		} else {
			// interface deleted in the meantime, so delete it from the map.
			delete(revs, ifid)
		}
	}
}

func (r *Revoker) pushRevocationsToBRs(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo) {

	topo := itopo.Get()
	msg := &path_mgmt.IFStateInfos{
		Infos: make([]*path_mgmt.IFStateInfo, 0, len(revs)),
	}
	for ifid, srev := range revs {
		msg.Infos = append(msg.Infos, &path_mgmt.IFStateInfo{
			IfID:     uint64(ifid),
			Active:   false,
			SRevInfo: srev,
		})
	}
	for brId, br := range topo.BR {
		a := &snet.Addr{
			IA:      topo.ISD_AS,
			Host:    br.CtrlAddrs.PublicAddr(topo.Overlay),
			NextHop: br.CtrlAddrs.OverlayAddr(topo.Overlay),
		}
		if err := r.msger.SendIfStateInfos(ctx, msg, a, messenger.NextId()); err != nil {
			log.Error("[Revoker] Failed to send revocations to BR", "br", brId, "err", err)
		}
	}
}

func (r *Revoker) pushRevocationsToPS(ctx context.Context,
	revs map[common.IFIDType]*path_mgmt.SignedRevInfo) {

	topo := itopo.Get()
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
