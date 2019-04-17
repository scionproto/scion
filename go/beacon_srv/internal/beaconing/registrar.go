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
	"time"

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
	cfg      Config
	mac      hash.Hash
	msgr     infra.Messenger
	intfs    *ifstate.Interfaces
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
		cfg:      cfg,
		mac:      mac,
		msgr:     msgr,
		intfs:    intfs,
		provider: provider,
		segType:  segType,
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
	var success, errors int
	for bOrErr := range segments {
		if err := r.handleBeaconOrErr(ctx, peers, bOrErr); err != nil {
			log.Error("[Registrar] Unable to register beacon", "type", r.segType, "err", err)
			errors++
			continue
		}
		success++
		log.Info("[Registrar] Successfully registered", "type", r.segType,
			"seg", bOrErr.Beacon.Segment)
	}
	if success <= 0 {
		return common.NewBasicError("No beacons propagated", nil, "errorCount", errors)
	}
	log.Info("[Registrar] Successfully registered segments", "count", success)
	return nil
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

func (r *Registrar) handleBeaconOrErr(ctx context.Context, peers []common.IFIDType,
	bOrErr beacon.BeaconOrErr) error {

	if bOrErr.Err != nil {
		return bOrErr.Err
	}
	if err := r.terminateSegment(bOrErr.Beacon, peers); err != nil {
		return common.NewBasicError("Unable to terminate beacon", err)
	}
	reg := &path_mgmt.SegReg{
		SegRecs: &path_mgmt.SegRecs{
			Recs: []*seg.Meta{
				{
					Type:    r.segType,
					Segment: bOrErr.Beacon.Segment,
				},
			},
		},
	}
	saddr, err := r.chooseServer(bOrErr.Beacon.Segment)
	if err != nil {
		return err
	}
	return r.msgr.SendSegReg(ctx, reg, saddr, messenger.NextId())
}

func (r *Registrar) terminateSegment(b beacon.Beacon, peers []common.IFIDType) error {
	infoF, err := b.Segment.InfoF()
	if err != nil {
		return common.NewBasicError("Unable to extract info field", err)
	}
	hopEntries, err := r.createHopEntries(b.InIfId, peers, infoF.Timestamp())
	if err != nil {
		return err
	}
	meta := r.cfg.Signer.Meta()
	asEntry := &seg.ASEntry{
		RawIA:      meta.Src.IA.IAInt(),
		CertVer:    meta.Src.ChainVer,
		TrcVer:     meta.Src.TRCVer,
		IfIDSize:   r.cfg.IfidSize,
		MTU:        r.cfg.MTU,
		HopEntries: hopEntries,
	}
	if err := b.Segment.AddASEntry(asEntry, r.cfg.Signer); err != nil {
		return err
	}
	return b.Segment.Validate(seg.ValidateSegment)

}

func (r *Registrar) createHopEntries(inIfid common.IFIDType, peers []common.IFIDType,
	ts time.Time) ([]*seg.HopEntry, error) {

	hopEntry, err := r.createHopEntry(inIfid, ts, nil)
	if err != nil {
		return nil, common.NewBasicError("Unable to create first hop entry", err)
	}
	hopEntries := []*seg.HopEntry{hopEntry}
	for _, ifid := range peers {
		hopEntry, err := r.createHopEntry(ifid, ts, hopEntries[0].RawHopField)
		if err != nil {
			log.Debug("[Registrar] Ignoring peer link upon error", "ifid", ifid, "err", err)
			continue
		}
		hopEntries = append(hopEntries, hopEntry)
	}
	return hopEntries, nil
}

func (r *Registrar) createHopEntry(inIfid common.IFIDType, ts time.Time,
	prev common.RawBytes) (*seg.HopEntry, error) {

	intf := r.intfs.Get(inIfid)
	if intf == nil {
		return nil, common.NewBasicError("Ingress interface not found", nil, "ifid", inIfid)
	}
	state := intf.State()
	if state != ifstate.Active {
		return nil, common.NewBasicError("Interface is not active", nil, "ifid", inIfid)
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.RemoteIFID == 0 {
		return nil, common.NewBasicError("Remote ifid is not set", nil)
	}
	if topoInfo.ISD_AS.IsWildcard() {
		return nil, common.NewBasicError("Remote IA is wildcard", nil, "ia", topoInfo.ISD_AS)
	}
	hopF, err := createHopF(inIfid, 0, ts, prev, r.cfg, r.mac)
	if err != nil {
		return nil, err
	}
	hop := &seg.HopEntry{
		RawHopField: hopF.Pack(),
		RawInIA:     topoInfo.ISD_AS.IAInt(),
		RemoteInIF:  topoInfo.RemoteIFID,
		InMTU:       uint16(topoInfo.MTU),
	}
	return hop, nil
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
