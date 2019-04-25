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
	segExtender
	sender *onehop.Sender
}

// NewOriginator creates a new originator. It takes ownership of the one-hop sender.
func NewOriginator(intfs *ifstate.Interfaces, cfg Config,
	sender *onehop.Sender) (*Originator, error) {

	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	o := &Originator{
		sender: sender,
		segExtender: segExtender{
			cfg:   cfg,
			intfs: intfs,
			mac:   sender.MAC,
			task:  "originator",
		},
	}
	return o, nil
}

// Run originates core and downstream beacons.
func (o *Originator) Run(_ context.Context) {
	intfs := o.intfs.All()
	o.originateBeacons(intfs, proto.LinkType_core)
	o.originateBeacons(intfs, proto.LinkType_child)
}

// originateBeacons creates and sends a beacon for each active interface of
// the specified link type.
func (o *Originator) originateBeacons(intfs map[common.IFIDType]*ifstate.Interface,
	linkType proto.LinkType) {

	infoF := o.createInfoF(time.Now())
	for ifid, info := range intfs {
		intf := info.TopoInfo()
		if intf.LinkType != linkType {
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
		return nil, common.NewBasicError("Unable to create segment", err)
	}
	if err := o.extend(bseg, 0, ifid, nil); err != nil {
		return nil, common.NewBasicError("Unable to extend segment", err)
	}
	return &seg.Beacon{Segment: bseg}, nil
}
