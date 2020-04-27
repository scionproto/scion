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
	"sync"
	"time"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
)

// segExtender appends AS entries to provided path segments.
type segExtender struct {
	cfg    ExtenderConf
	macMtx sync.Mutex
}

func (cfg ExtenderConf) new() (*segExtender, error) {
	cfg.InitDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &segExtender{cfg: cfg}, nil
}

// extend extends the path segment. Prev should include the full raw hop field,
// if any, including the flags byte. A zero ingress interface indicates, that
// the created AS entry is the initial entry. A zero egress interface indicates,
// that the segment is terminated.
func (s *segExtender) extend(pseg *seg.PathSegment, inIfid, egIfid common.IFIDType,
	peers []common.IFIDType) error {

	if inIfid == 0 && egIfid == 0 {
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
	hopEntries, err := s.createHopEntries(inIfid, egIfid, peers, prev, infoF.Timestamp())
	if err != nil {
		return err
	}
	staticInfoPeers := seg.CreatePeerMap(s.cfg)
	staticInfo := seg.GenerateStaticinfo(s.cfg.StaticInfoCfg, staticInfoPeers, uint16(egIfid), uint16(inIfid))
	meta := s.cfg.Signer.Meta()
	asEntry := &seg.ASEntry{
		RawIA:      meta.Src.IA.IAInt(),
		CertVer:    meta.Src.ChainVer,
		TrcVer:     meta.Src.TRCVer,
		IfIDSize:   s.cfg.IfidSize,
		MTU:        s.cfg.MTU,
		HopEntries: hopEntries,
	}
	asEntry.Exts.StaticInfo = &staticInfo
	if err := pseg.AddASEntry(asEntry, s.cfg.Signer); err != nil {
		return err
	}
	if egIfid == 0 {
		return pseg.Validate(seg.ValidateSegment)
	}
	return pseg.Validate(seg.ValidateBeacon)
}

func (s *segExtender) createHopEntries(inIfid, egIfid common.IFIDType, peers []common.IFIDType,
	prev common.RawBytes, ts time.Time) ([]*seg.HopEntry, error) {

	hopEntry, err := s.createHopEntry(inIfid, egIfid, prev, ts)
	if err != nil {
		return nil, common.NewBasicError("Unable to create first hop entry", err)
	}
	hopEntries := []*seg.HopEntry{hopEntry}
	for _, ifid := range peers {
		hopEntry, err := s.createHopEntry(ifid, egIfid, hopEntries[0].RawHopField, ts)
		if err != nil {
			log.Debug("Ignoring peer link upon error", "task", s.cfg.task, "ifid", ifid, "err", err)
			continue
		}
		hopEntries = append(hopEntries, hopEntry)
	}
	return hopEntries, nil
}

func (s *segExtender) createHopEntry(inIfid, egIfid common.IFIDType, prev common.RawBytes,
	ts time.Time) (*seg.HopEntry, error) {

	remoteInIA, remoteInIfid, remoteInMtu, err := s.remoteInfo(inIfid)
	if err != nil {
		return nil, common.NewBasicError("Invalid remote ingress interface", err, "ifid", inIfid)
	}
	remoteOutIA, remoteOutIfid, _, err := s.remoteInfo(egIfid)
	if err != nil {
		return nil, common.NewBasicError("Invalid remote egress interface", err, "ifid", egIfid)
	}
	hopF, err := s.createHopF(inIfid, egIfid, prev, ts)
	if err != nil {
		return nil, err
	}
	hop := &seg.HopEntry{
		RawHopField: hopF.Pack(),
		RawInIA:     remoteInIA,
		RemoteInIF:  remoteInIfid,
		InMTU:       uint16(remoteInMtu),
		RawOutIA:    remoteOutIA,
		RemoteOutIF: remoteOutIfid,
	}
	return hop, nil
}

func (s *segExtender) remoteInfo(ifid common.IFIDType) (
	addr.IAInt, common.IFIDType, uint16, error) {

	if ifid == 0 {
		return 0, 0, 0, nil
	}
	intf := s.cfg.Intfs.Get(ifid)
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
func (s *segExtender) createHopF(inIfid, egIfid common.IFIDType, prev common.RawBytes,
	ts time.Time) (*spath.HopField, error) {

	meta := s.cfg.Signer.Meta()
	diff := meta.ExpTime.Sub(ts)
	if diff < 1*time.Hour {
		log.Warn("Signer expiration time is near", "task", s.cfg.task, "ts", ts,
			"chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	expiry, err := spath.ExpTimeFromDuration(diff, false)
	if err != nil {
		min := ts.Add(spath.ExpTimeType(0).ToDuration())
		return nil, common.NewBasicError("Chain does not cover minimum hop expiration time", nil,
			"minimumExpiration", min, "chainExpiration", meta.ExpTime, "src", meta.Src)
	}
	expiry = min(expiry, s.cfg.GetMaxExpTime())
	hop := &spath.HopField{
		ConsIngress: inIfid,
		ConsEgress:  egIfid,
		ExpTime:     expiry,
	}
	if prev != nil {
		// Do not include the flags of the hop field in the mac input.
		prev = prev[1:]
	}
	s.macMtx.Lock()
	defer s.macMtx.Unlock()
	hop.Mac = hop.CalcMac(s.cfg.Mac, util.TimeToSecs(ts), prev)
	return hop, nil
}

// IntfActive returns whether the interface is active.
func (s *segExtender) IntfActive(ifid common.IFIDType) bool {
	intf := s.cfg.Intfs.Get(ifid)
	return intf != nil && intf.State() == ifstate.Active
}

func min(a, b spath.ExpTimeType) spath.ExpTimeType {
	if a > b {
		return b
	}
	return a
}
