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

package propagation

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/beacon_srv/internal/ifstate"
	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ periodic.Task = (*Originator)(nil)

// Originator originates beacons. It should only be used by core ASes.
type Originator struct {
	sender  *onehop.Sender
	cfg     Config
	ifState *ifstate.Infos
}

// NewOriginator creates a new originator. It takes ownership of the
// one-hop sender.
func NewOriginator(infos *ifstate.Infos, cfg Config, sender *onehop.Sender) (*Originator, error) {
	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	o := &Originator{
		sender:  sender,
		cfg:     cfg,
		ifState: infos,
	}
	return o, nil
}

// Run originates core and downstream beacons.
func (o *Originator) Run(_ context.Context) {
	infos := o.ifState.All()
	o.originateBeacons(infos, proto.LinkType_core)
	o.originateBeacons(infos, proto.LinkType_child)
}

// originateBeacons creates and sends a beacon for each active interface of
// the specified link type.
func (o *Originator) originateBeacons(infos map[common.IFIDType]*ifstate.Info, lt proto.LinkType) {
	infoF := o.createInfoF(time.Now())
	for ifid, info := range infos {
		intf := info.TopoInfo()
		if intf.LinkType != lt {
			continue
		}
		state := info.State()
		if state != ifstate.Active {
			log.Debug("[Originator] Skipping non-active interface", "ifid", ifid, "state", state)
			continue
		}
		msg, err := o.createBeaconMsg(ifid, intf, infoF)
		if err != nil {
			log.Error("[Originator] Skipping interface on error", "ifid", ifid, "err", err)
			continue
		}
		ov := intf.InternalAddrs.PublicOverlay(intf.InternalAddrs.Overlay)
		if err := o.sender.Send(msg, ov); err != nil {
			log.Error("[Originator] Unable to send packet", "ifid", "err", err)
		}
	}
}

// crateInfoF creates the info field.
func (o *Originator) createInfoF(now time.Time) spath.InfoField {
	infoF := spath.InfoField{
		ConsDir: true,
		ISD:     uint16(o.sender.IA.I),
		TsInt:   util.TimeToSecs(now),
	}
	return infoF
}

// createBeaconMsg creates a beacon for the given interface, signs it and
// wraps it in a one-hop message.
func (o *Originator) createBeaconMsg(ifid common.IFIDType, intf topology.IFInfo,
	infoF spath.InfoField) (*onehop.Msg, error) {

	bseg, err := o.createBeacon(ifid, intf, infoF)
	if err != nil {
		return nil, common.NewBasicError("Unable to create beacon", err, "ifid", ifid)
	}
	pld, err := ctrl.NewPld(bseg, nil)
	if err != nil {
		return nil, common.NewBasicError("Unable to create payload", err)
	}
	spld, err := pld.SignedPld(o.cfg.Signer)
	if err != nil {
		return nil, common.NewBasicError("Unable to sign payload", err)
	}
	packed, err := spld.PackPld()
	if err != nil {
		return nil, common.NewBasicError("Unable to pack payload", err)
	}
	msg := &onehop.Msg{
		Dst: snet.SCIONAddress{
			IA:   intf.ISD_AS,
			Host: addr.SvcBS,
		},
		Ifid:     ifid,
		InfoTime: time.Now(),
		Pld:      packed,
	}
	return msg, nil
}

func (o *Originator) createBeacon(ifid common.IFIDType, intf topology.IFInfo,
	infoF spath.InfoField) (*seg.Beacon, error) {

	bseg, err := seg.NewSeg(&infoF)
	if err != nil {
		return nil, err
	}
	hopEntries, err := o.createHopEntry(ifid, intf, infoF.Timestamp())
	if err != nil {
		return nil, err
	}
	meta := o.cfg.Signer.Meta()
	asEntry := &seg.ASEntry{
		RawIA:      meta.Src.IA.IAInt(),
		CertVer:    meta.Src.ChainVer,
		TrcVer:     meta.Src.TRCVer,
		IfIDSize:   o.cfg.IfidSize,
		MTU:        o.cfg.MTU,
		HopEntries: hopEntries,
	}
	if err := bseg.AddASEntry(asEntry, o.cfg.Signer); err != nil {
		return nil, err
	}
	return &seg.Beacon{Segment: bseg}, nil
}

func (o *Originator) createHopEntry(ifid common.IFIDType, intf topology.IFInfo,
	ts time.Time) ([]*seg.HopEntry, error) {

	if intf.RemoteIFID == 0 {
		return nil, common.NewBasicError("Remote ifid is not set", nil)
	}
	if intf.ISD_AS.IsWildcard() {
		return nil, common.NewBasicError("Remote IA is wildcard", nil, "ia", intf.ISD_AS)
	}
	rawHopF, err := o.createRawHop(ifid, ts)
	if err != nil {
		return nil, err
	}
	hop := &seg.HopEntry{
		RawHopField: rawHopF,
		RawOutIA:    intf.ISD_AS.IAInt(),
		RemoteOutIF: intf.RemoteIFID,
	}
	return []*seg.HopEntry{hop}, nil
}

func (o *Originator) createRawHop(ifid common.IFIDType, ts time.Time) (common.RawBytes, error) {
	meta := o.cfg.Signer.Meta()
	diff := meta.ExpTime.Sub(ts)
	if diff < 30*time.Minute {
		log.Warn("[Originator] Signer expiration time is near",
			"chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	expiry, err := spath.ExpTimeFromDuration(diff, false)
	if err != nil {
		min := ts.Add(spath.ExpTimeType(0).ToDuration())
		return nil, common.NewBasicError("Chain does not cover minimum hop expiration time", nil,
			"minimumExpiration", min, "chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	if expiry > spath.DefaultHopFExpiry {
		expiry = spath.DefaultHopFExpiry
	}
	hop := &spath.HopField{
		ConsEgress: ifid,
		ExpTime:    expiry,
	}
	if hop.Mac, err = hop.CalcMac(o.sender.MAC, util.TimeToSecs(ts), nil); err != nil {
		return nil, common.NewBasicError("Unable to create MAC", err)
	}
	return hop.Pack(), nil
}
