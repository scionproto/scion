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

	"github.com/scionproto/scion/go/beacon_srv/internal/onehop"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

var _ periodic.Task = (*Originator)(nil)

// OriginatorConf is the configuration to create a new originator.
type OriginatorConf struct {
	Config ExtenderConf
	Sender *onehop.Sender
}

// Originator originates beacons. It should only be used by core ASes.
type Originator struct {
	*segExtender
	sender *onehop.Sender
}

// New creates a new originator.
func (cfg OriginatorConf) New() (*Originator, error) {

	cfg.Config.task = "originator"
	extender, err := cfg.Config.new()
	if err != nil {
		return nil, err
	}
	o := &Originator{
		sender:      cfg.Sender,
		segExtender: extender,
	}
	return o, nil
}

// Run originates core and downstream beacons.
func (o *Originator) Run(_ context.Context) {
	o.originateBeacons(proto.LinkType_core)
	o.originateBeacons(proto.LinkType_child)
}

// originateBeacons creates and sends a beacon for each active interface of
// the specified link type.
func (o *Originator) originateBeacons(linkType proto.LinkType) {

	active, nonActive := sortedIntfs(o.cfg.Intfs, linkType)
	if len(nonActive) > 0 {
		log.Debug("[Originator] Ignore non-active interfaces", "intfs", nonActive)
	}
	infoF := o.createInfoF(time.Now())
	for _, ifid := range active {
		if err := o.originateBeacon(ifid, infoF); err != nil {
			log.Error("[Originator] Unable to originate on interface", "ifid", ifid, "err", err)
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

// originateBeacon originates a beacon on the given ifid.
func (o *Originator) originateBeacon(ifid common.IFIDType, infoF spath.InfoField) error {
	intf := o.cfg.Intfs.Get(ifid)
	if intf == nil {
		return common.NewBasicError("Interface does not exist", nil)
	}
	topoInfo := intf.TopoInfo()
	msg, err := o.createBeaconMsg(ifid, infoF, topoInfo.ISD_AS)
	if err != nil {
		return err
	}
	ov := topoInfo.InternalAddrs.PublicOverlay(topoInfo.InternalAddrs.Overlay)
	if err := o.sender.Send(msg, ov); err != nil {
		return common.NewBasicError("Unable to send packet", err)
	}
	return nil
}

// createBeaconMsg creates a beacon for the given interface, signs it and
// wraps it in a one-hop message.
func (o *Originator) createBeaconMsg(ifid common.IFIDType, infoF spath.InfoField,
	remoteIA addr.IA) (*onehop.Msg, error) {

	bseg, err := o.createBeacon(ifid, infoF)
	if err != nil {
		return nil, common.NewBasicError("Unable to create beacon", err, "ifid", ifid)
	}
	return packBeaconMsg(bseg, remoteIA, ifid, o.cfg.Signer)
}

func (o *Originator) createBeacon(ifid common.IFIDType,
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
