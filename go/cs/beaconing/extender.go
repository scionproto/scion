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
	"encoding/binary"
	"hash"
	"time"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/digest"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/epic"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/util"
)

// Extender extends path segments.
type Extender interface {
	// Extend extends the path segment. The zero value for ingress indicates
	// that the created AS entry is the initial entry in a path. The zero value
	// for egress indicates that the created AS entry is the last entry in the
	// path, and the beacon is terminated.
	Extend(ctx context.Context, seg *seg.PathSegment, ingress, egress common.IFIDType,
		peers []common.IFIDType) error
}

// DefaultExtender extends provided path segments with entries for the local AS.
type DefaultExtender struct {
	// IA is the local IA
	IA addr.IA
	// Signer is used to sign path segments.
	Signer seg.Signer
	// MAC is used to calculate the hop field MAC.
	MAC func() hash.Hash
	// Intfs holds all interfaces in the AS.
	Intfs *ifstate.Interfaces
	// MTU is the MTU value set in the AS entries.
	MTU uint16
	// GetMaxExpTime returns the maximum relative expiration time.
	MaxExpTime func() uint8
	// Task contains an identifier specific to the task that uses the extender.
	Task string
	// StaticInfo contains the configuration used for the StaticInfo Extension.
	StaticInfo func() *StaticInfoCfg
	// EPIC defines whether the EPIC authenticators should be added when the segment is extended.
	EPIC bool
}

// Extend extends the beacon with hop fields of the old format.
func (s *DefaultExtender) Extend(ctx context.Context, pseg *seg.PathSegment,
	ingress, egress common.IFIDType, peers []common.IFIDType) error {

	if s.MTU == 0 {
		return serrors.New("MTU not set")
	}
	firstHop := pseg.MaxIdx() < 0
	if ingress == 0 && !firstHop {
		return serrors.New("ingress must only be zero in first hop")
	}
	if ingress != 0 && firstHop {
		return serrors.New("ingress must be zero in first hop", "ingress_interface", ingress)
	}
	if ingress == 0 && egress == 0 {
		return serrors.New("ingress and egress must not be both 0")
	}
	ts := pseg.Info.Timestamp

	hopEntry, epicHopMac, err := s.createHopEntry(ingress, egress, ts, extractBeta(pseg))
	if err != nil {
		return serrors.WrapStr("creating hop entry", err)
	}
	peerBeta := extractBeta(pseg) ^ binary.BigEndian.Uint16(hopEntry.HopField.MAC[:2])
	peerEntries, epicPeerMacs, err := s.createPeerEntries(egress, peers, ts, peerBeta)
	if err != nil {
		return err
	}
	next, err := s.remoteIA(egress)
	if err != nil {
		return err
	}
	asEntry := seg.ASEntry{
		HopEntry:    hopEntry,
		Local:       s.IA,
		Next:        next.IA(),
		PeerEntries: peerEntries,
		MTU:         int(s.MTU),
	}
	if static := s.StaticInfo(); static != nil {
		asEntry.Extensions.StaticInfo = static.Generate(s.Intfs, ingress, egress)
	}

	// Add the detachable Epic extension
	if s.EPIC {
		e := &epic.Detached{
			AuthHopEntry:    epicHopMac,
			AuthPeerEntries: epicPeerMacs,
		}
		asEntry.UnsignedExtensions.EpicDetached = e

		var d digest.Digest
		input, err := e.DigestInput()
		if err != nil {
			return err
		}
		d.Set(input)

		asEntry.Extensions.Digests = &digest.Extension{
			Epic: d,
		}
	}

	if err := pseg.AddASEntry(ctx, asEntry, s.Signer); err != nil {
		return err
	}
	if egress == 0 {
		return pseg.Validate(seg.ValidateSegment)
	}
	return pseg.Validate(seg.ValidateBeacon)
}

func (s *DefaultExtender) createPeerEntries(egress common.IFIDType, peers []common.IFIDType,
	ts time.Time, beta uint16) ([]seg.PeerEntry, [][]byte, error) {

	peerEntries := make([]seg.PeerEntry, 0, len(peers))
	peerEpicMacs := make([][]byte, 0, len(peers))
	for _, peer := range peers {
		peerEntry, epicMac, err := s.createPeerEntry(peer, egress, ts, beta)
		if err != nil {
			log.Debug("Ignoring peer link upon error",
				"task", s.Task, "peer_interface", peer, "err", err)
			continue
		}
		peerEntries = append(peerEntries, peerEntry)
		peerEpicMacs = append(peerEpicMacs, epicMac)
	}
	return peerEntries, peerEpicMacs, nil
}

func (s *DefaultExtender) createHopEntry(ingress, egress common.IFIDType, ts time.Time,
	beta uint16) (seg.HopEntry, []byte, error) {

	remoteInMTU, err := s.remoteMTU(ingress)
	if err != nil {
		return seg.HopEntry{}, nil, serrors.WrapStr("checking remote ingress interface (mtu)", err,
			"interfaces", ingress)
	}
	hopF, epicMac := s.createHopF(uint16(ingress), uint16(egress), ts, beta)
	return seg.HopEntry{
		IngressMTU: int(remoteInMTU),
		HopField: seg.HopField{
			ConsIngress: hopF.ConsIngress,
			ConsEgress:  hopF.ConsEgress,
			ExpTime:     hopF.ExpTime,
			MAC:         hopF.Mac,
		},
	}, epicMac, nil
}

func (s *DefaultExtender) createPeerEntry(ingress, egress common.IFIDType, ts time.Time,
	beta uint16) (seg.PeerEntry, []byte, error) {

	remoteInIA, remoteInIfID, remoteInMTU, err := s.remoteInfo(ingress)
	if err != nil {
		return seg.PeerEntry{}, nil, serrors.WrapStr("checking remote ingress interface", err,
			"ingress_interface", ingress)
	}
	hopF, epicMac := s.createHopF(uint16(ingress), uint16(egress), ts, beta)
	return seg.PeerEntry{
		PeerMTU:       int(remoteInMTU),
		Peer:          remoteInIA.IA(),
		PeerInterface: uint16(remoteInIfID),
		HopField: seg.HopField{
			ConsIngress: hopF.ConsIngress,
			ConsEgress:  hopF.ConsEgress,
			ExpTime:     hopF.ExpTime,
			MAC:         hopF.Mac,
		},
	}, epicMac, nil
}

func (s *DefaultExtender) remoteIA(ifID common.IFIDType) (addr.IAInt, error) {
	if ifID == 0 {
		return 0, nil
	}
	intf := s.Intfs.Get(ifID)
	if intf == nil {
		return 0, serrors.New("interface not found")
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.IA.IsWildcard() {
		return 0, serrors.New("remote is wildcard", "isd_as", topoInfo.IA)
	}
	return topoInfo.IA.IAInt(), nil
}

func (s *DefaultExtender) remoteMTU(ifID common.IFIDType) (uint16, error) {
	if ifID == 0 {
		return 0, nil
	}
	intf := s.Intfs.Get(ifID)
	if intf == nil {
		return 0, serrors.New("interface not found")
	}
	topoInfo := intf.TopoInfo()
	return uint16(topoInfo.MTU), nil
}

func (s *DefaultExtender) remoteInfo(ifid common.IFIDType) (
	addr.IAInt, common.IFIDType, uint16, error) {

	if ifid == 0 {
		return 0, 0, 0, nil
	}
	intf := s.Intfs.Get(ifid)
	if intf == nil {
		return 0, 0, 0, serrors.New("interface not found")
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.RemoteIFID == 0 {
		return 0, 0, 0, serrors.New("remote interface ID is not set")
	}
	if topoInfo.IA.IsWildcard() {
		return 0, 0, 0, serrors.New("remote ISD-AS is wildcard", "isd_as", topoInfo.IA)
	}
	return topoInfo.IA.IAInt(), topoInfo.RemoteIFID, uint16(topoInfo.MTU), nil
}

func (s *DefaultExtender) createHopF(ingress, egress uint16, ts time.Time,
	beta uint16) (path.HopField, []byte) {

	expTime := s.MaxExpTime()
	input := path.MACInput(beta, util.TimeToSecs(ts), expTime, ingress, egress)

	mac := s.MAC()
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := mac.Write(input); err != nil {
		panic(err)
	}
	fullMAC := mac.Sum(nil)
	return path.HopField{
		ConsIngress: ingress,
		ConsEgress:  egress,
		ExpTime:     expTime,
		Mac:         fullMAC[:6],
	}, fullMAC[6:16]
}

func extractBeta(pseg *seg.PathSegment) uint16 {
	beta := pseg.Info.SegmentID
	for _, entry := range pseg.ASEntries {
		sigma := binary.BigEndian.Uint16(entry.HopEntry.HopField.MAC[:2])
		beta = beta ^ sigma
	}
	return beta
}
