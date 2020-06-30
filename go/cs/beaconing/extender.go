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
	"time"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

// legacyIfIDSize is the default bit-size for ifids in the hop-fields.
const legacyIfIDSize = 12

// Extender extends path segments.
type Extender interface {
	// Extend extends the path segment. The zero value for ingress indicates
	// that the created AS entry is the initial entry in a path. The zero value
	// for egress indicates that the created AS entry is the last entry in the
	// path, and the beacon is terminated.
	Extend(ctx context.Context, seg *seg.PathSegment, ingress, egress common.IFIDType,
		peers []common.IFIDType) error
}

// LegacyExtender appends AS entries to provided path segments.
type LegacyExtender struct {
	// IA is the local IA
	IA addr.IA
	// Signer is used to sign path segments.
	Signer ctrl.Signer
	// MAC is used to calculate the hop field MAC.
	MAC func() hash.Hash
	// Intfs holds all interfaces in the AS.
	Intfs *ifstate.Interfaces
	// MTU is the MTU value set in the AS entries.
	MTU uint16
	// GetMaxExpTime returns the maximum relative expiration time.
	MaxExpTime func() spath.ExpTimeType
	// Task contains an identifier specific to the task that uses the extender.
	Task string
	// StaticInfo contains the configuration used for the StaticInfo Extension.
	StaticInfo func() *StaticInfoCfg
}

// Extend extends the beacon with hop fields of the old format.
func (s *LegacyExtender) Extend(ctx context.Context, pseg *seg.PathSegment,
	ingress, egress common.IFIDType, peers []common.IFIDType) error {

	if s.MTU == 0 {
		return serrors.New("MTU not set")
	}
	if ingress == 0 && egress == 0 {
		return serrors.New("Ingress and egress must not be both 0")
	}
	infoF, err := pseg.InfoF()
	if err != nil {
		return common.NewBasicError("Unable to extract info field", err)
	}
	var prev common.RawBytes
	if pseg.MaxAEIdx() >= 0 {
		// Validated segments are guaranteed to have at least one hop entry.
		prev = pseg.ASEntries[pseg.MaxAEIdx()].HopEntries[0].RawHopField
	}
	hopEntries, err := s.createHopEntries(ingress, egress, peers, prev, infoF.Timestamp())
	if err != nil {
		return err
	}
	asEntry := &seg.ASEntry{
		RawIA:      s.IA.IAInt(),
		IfIDSize:   legacyIfIDSize,
		MTU:        s.MTU,
		HopEntries: hopEntries,
	}
	if static := s.StaticInfo(); static != nil {
		staticInfoPeers := createPeerMap(s.Intfs)
		staticInfo := static.generateStaticinfo(staticInfoPeers, egress, ingress)
		asEntry.Exts.StaticInfo = &staticInfo
	}
	if err := pseg.AddASEntry(ctx, asEntry, s.Signer); err != nil {
		return err
	}
	if egress == 0 {
		return pseg.Validate(seg.ValidateSegment)
	}
	return pseg.Validate(seg.ValidateBeacon)
}

func (s *LegacyExtender) createHopEntries(ingress, egress common.IFIDType, peers []common.IFIDType,
	prev common.RawBytes, ts time.Time) ([]*seg.HopEntry, error) {

	hopEntry, err := s.createHopEntry(ingress, egress, prev, ts)
	if err != nil {
		return nil, common.NewBasicError("Unable to create first hop entry", err)
	}
	hopEntries := []*seg.HopEntry{hopEntry}
	for _, ifid := range peers {
		hopEntry, err := s.createHopEntry(ifid, egress, hopEntries[0].RawHopField, ts)
		if err != nil {
			log.Debug("Ignoring peer link upon error", "task", s.Task, "ifid", ifid, "err", err)
			continue
		}
		hopEntries = append(hopEntries, hopEntry)
	}
	return hopEntries, nil
}

func (s *LegacyExtender) createHopEntry(ingress, egress common.IFIDType, prev common.RawBytes,
	ts time.Time) (*seg.HopEntry, error) {

	remoteInIA, remoteInIfID, remoteInMtu, err := s.remoteInfo(ingress)
	if err != nil {
		return nil, common.NewBasicError("Invalid remote ingress interface", err, "ifid", ingress)
	}
	remoteOutIA, remoteOutIfid, _, err := s.remoteInfo(egress)
	if err != nil {
		return nil, common.NewBasicError("Invalid remote egress interface", err, "ifid", egress)
	}
	hopF, err := s.createHopF(ingress, egress, prev, ts)
	if err != nil {
		return nil, err
	}
	hop := &seg.HopEntry{
		RawHopField: hopF.Pack(),
		RawInIA:     remoteInIA,
		RemoteInIF:  remoteInIfID,
		InMTU:       uint16(remoteInMtu),
		RawOutIA:    remoteOutIA,
		RemoteOutIF: remoteOutIfid,
	}
	return hop, nil
}

func (s *LegacyExtender) remoteInfo(ifid common.IFIDType) (
	addr.IAInt, common.IFIDType, uint16, error) {

	if ifid == 0 {
		return 0, 0, 0, nil
	}
	intf := s.Intfs.Get(ifid)
	if intf == nil {
		return 0, 0, 0, serrors.New("Interface not found")
	}
	state := intf.State()
	if state != ifstate.Active {
		return 0, 0, 0, serrors.New("Interface is not active")
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.RemoteIFID == 0 {
		return 0, 0, 0, serrors.New("Remote ifid is not set")
	}
	if topoInfo.IA.IsWildcard() {
		return 0, 0, 0, common.NewBasicError("Remote IA is wildcard", nil, "ia", topoInfo.IA)
	}
	return topoInfo.IA.IAInt(), topoInfo.RemoteIFID, uint16(topoInfo.MTU), nil
}

// createHopF creates a hop field with the provided parameters. The previous hop
// field, if any, must contain all raw bytes including the flags.
func (s *LegacyExtender) createHopF(ingress, egress common.IFIDType, prev common.RawBytes,
	ts time.Time) (*spath.HopField, error) {

	hop := &spath.HopField{
		ConsIngress: ingress,
		ConsEgress:  egress,
		ExpTime:     s.MaxExpTime(),
	}
	if prev != nil {
		// Do not include the flags of the hop field in the mac input.
		prev = prev[1:]
	}
	hop.Mac = hop.CalcMac(s.MAC(), util.TimeToSecs(ts), prev)
	return hop, nil
}

func intfActive(intfs *ifstate.Interfaces, ifid common.IFIDType) bool {
	intf := intfs.Get(ifid)
	return intf != nil && intf.State() == ifstate.Active
}

func min(a, b spath.ExpTimeType) spath.ExpTimeType {
	if a > b {
		return b
	}
	return a
}

// createPeerMap creates a set of peers indicating whether the
// interface identified by the key is used for peering or not.
func createPeerMap(intfs *ifstate.Interfaces) map[common.IFIDType]struct{} {
	peers := make(map[common.IFIDType]struct{})
	for ifID, ifInfo := range intfs.All() {
		if ifInfo.TopoInfo().LinkType == topology.Peer {
			peers[ifID] = struct{}{}
		}
	}
	return peers
}
