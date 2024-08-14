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

	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/digest"
	"github.com/scionproto/scion/pkg/segment/extensions/epic"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/private/trust"
)

// SignerGen generates signers and returns their expiration time.
type SignerGen interface {
	// Generate generates a signer it.
	Generate(ctx context.Context) ([]Signer, error)
}

type Signer interface {
	Sign(context.Context, []byte, ...[]byte) (*cryptopb.SignedMessage, error)
	Validity() cppki.Validity
}

type SignerGenFunc func(ctx context.Context) ([]Signer, error)

func (f SignerGenFunc) Generate(ctx context.Context) ([]Signer, error) {
	return f(ctx)
}

// Extender extends path segments.
type Extender interface {
	// Extend extends the path segment. The zero value for ingress indicates
	// that the created AS entry is the initial entry in a path. The zero value
	// for egress indicates that the created AS entry is the last entry in the
	// path, and the beacon is terminated.
	Extend(ctx context.Context, seg *seg.PathSegment, ingress, egress uint16, peers []uint16) error
}

// DefaultExtender extends provided path segments with entries for the local AS.
type DefaultExtender struct {
	// IA is the local IA
	IA addr.IA
	// SignerGen is used to sign path segments.
	SignerGen SignerGen
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

	// SegmentExpirationDeficient is a gauge that is set to 1 if the expiration time of the segment
	// is below the maximum expiration time. This happens when the signer expiration time is lower
	// than the maximum segment expiration time.
	SegmentExpirationDeficient metrics.Gauge
}

// Extend extends the beacon with hop fields.
func (s *DefaultExtender) Extend(
	ctx context.Context,
	pseg *seg.PathSegment,
	ingress, egress uint16,
	peers []uint16,
) error {

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

	signers, err := s.SignerGen.Generate(ctx)
	if err != nil {
		return serrors.Wrap("getting signer", err)
	}
	now := time.Now()
	signer, err := trust.LastExpiring(signers, cppki.Validity{
		NotBefore: pseg.Info.Timestamp,
		NotAfter:  now,
	})
	if err != nil {
		return serrors.Wrap("selecting signer", err)
	}
	// Make sure the hop expiration time is not longer than the signer expiration time.
	expTime := s.MaxExpTime()
	signerExp := signer.Validity().NotAfter
	if ts.Add(path.ExpTimeToDuration(expTime)).After(signerExp) {
		metrics.GaugeSet(s.SegmentExpirationDeficient, 1)
		var err error
		expTime, err = path.ExpTimeFromDuration(signerExp.Sub(ts))
		if err != nil {
			return serrors.Wrap(
				"calculating expiry time from signer expiration time", err,
				"signer_expiration", signerExp,
			)
		}
	} else {
		metrics.GaugeSet(s.SegmentExpirationDeficient, 0)
	}
	hopBeta := extractBeta(pseg)
	hopEntry, epicHopMac, err := s.createHopEntry(ingress, egress, expTime, ts, hopBeta)
	if err != nil {
		return serrors.Wrap("creating hop entry", err)
	}

	// The peer hop fields chain to the main hop field, just like any child hop field.
	// The effect of this is that when a peer hop field is used in a path, both the
	// peer hop field and its child are validated using the same SegID accumlator value:
	// that originally intended for the child.
	//
	// The corrolary is that one cannot validate a hop field's MAC by looking at the
	// parent hop field MAC when the parent is a peering hop field. This is ok: that
	// is never done that way, it is always done by validating against the SegID
	// accumulator supplied by the previous router on the forwarding path. The
	// forwarding code takes care of not updating that accumulator when a peering hop
	// is traversed.

	peerBeta := hopBeta ^ binary.BigEndian.Uint16(hopEntry.HopField.MAC[:2])
	peerEntries, epicPeerMacs, err := s.createPeerEntries(egress, peers, expTime, ts, peerBeta)
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
		Next:        next,
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

	if err := pseg.AddASEntry(ctx, asEntry, signer); err != nil {
		return err
	}
	if egress == 0 {
		return pseg.Validate(seg.ValidateSegment)
	}
	return pseg.Validate(seg.ValidateBeacon)
}

func (s *DefaultExtender) createPeerEntries(egress uint16, peers []uint16,
	expTime uint8, ts time.Time, beta uint16) ([]seg.PeerEntry, [][]byte, error) {

	peerEntries := make([]seg.PeerEntry, 0, len(peers))
	peerEpicMacs := make([][]byte, 0, len(peers))
	for _, peer := range peers {
		peerEntry, epicMac, err := s.createPeerEntry(peer, egress, expTime, ts, beta)
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

func (s *DefaultExtender) createHopEntry(
	ingress,
	egress uint16,
	expTime uint8,
	ts time.Time,
	beta uint16,
) (seg.HopEntry, []byte, error) {

	remoteInMTU, err := s.remoteMTU(ingress)
	if err != nil {
		return seg.HopEntry{}, nil, serrors.Wrap("checking remote ingress interface (mtu)", err,
			"interfaces", ingress)
	}
	hopF, epicMac := s.createHopF(ingress, egress, expTime, ts, beta)
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

func (s *DefaultExtender) createPeerEntry(ingress, egress uint16, expTime uint8, ts time.Time,
	beta uint16) (seg.PeerEntry, []byte, error) {

	remoteInIA, remoteInIfID, remoteInMTU, err := s.remoteInfo(ingress)
	if err != nil {
		return seg.PeerEntry{}, nil, serrors.Wrap("checking remote ingress interface", err,
			"ingress_interface", ingress)
	}
	hopF, epicMac := s.createHopF(ingress, egress, expTime, ts, beta)
	return seg.PeerEntry{
		PeerMTU:       int(remoteInMTU),
		Peer:          remoteInIA,
		PeerInterface: remoteInIfID,
		HopField: seg.HopField{
			ConsIngress: hopF.ConsIngress,
			ConsEgress:  hopF.ConsEgress,
			ExpTime:     hopF.ExpTime,
			MAC:         hopF.Mac,
		},
	}, epicMac, nil
}

func (s *DefaultExtender) remoteIA(ifID uint16) (addr.IA, error) {
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
	return topoInfo.IA, nil
}

func (s *DefaultExtender) remoteMTU(ifID uint16) (uint16, error) {
	if ifID == 0 {
		return 0, nil
	}
	intf := s.Intfs.Get(ifID)
	if intf == nil {
		return 0, serrors.New("interface not found")
	}
	topoInfo := intf.TopoInfo()
	return topoInfo.MTU, nil
}

func (s *DefaultExtender) remoteInfo(ifID uint16) (
	addr.IA, uint16, uint16, error) {

	if ifID == 0 {
		return 0, 0, 0, nil
	}
	intf := s.Intfs.Get(ifID)
	if intf == nil {
		return 0, 0, 0, serrors.New("interface not found")
	}
	topoInfo := intf.TopoInfo()
	if topoInfo.RemoteID == 0 {
		return 0, 0, 0, serrors.New("remote interface ID is not set")
	}
	if topoInfo.IA.IsWildcard() {
		return 0, 0, 0, serrors.New("remote ISD-AS is wildcard", "isd_as", topoInfo.IA)
	}
	return topoInfo.IA, topoInfo.RemoteID, topoInfo.MTU, nil
}

func (s *DefaultExtender) createHopF(ingress, egress uint16, expTime uint8, ts time.Time,
	beta uint16) (path.HopField, []byte) {

	input := make([]byte, path.MACBufferSize)
	path.MACInput(beta, util.TimeToSecs(ts), expTime, ingress, egress, input)

	mac := s.MAC()
	// Write must not return an error: https://godoc.org/hash#Hash
	if _, err := mac.Write(input); err != nil {
		panic(err)
	}
	fullMAC := mac.Sum(nil)
	m := [path.MacLen]byte{}
	copy(m[:], fullMAC[:path.MacLen])
	return path.HopField{
		ConsIngress: ingress,
		ConsEgress:  egress,
		ExpTime:     expTime,
		Mac:         m,
	}, fullMAC[path.MacLen:]
}

// extractBeta computes the beta value that must be used for the next hop to be
// added at the end of the segment.
// FIXME(jice): keeping an accumulator would be just as easy to do as it is during
// forwarding. What's the benefit of re-calculating the whole chain every time?
func extractBeta(pseg *seg.PathSegment) uint16 {
	beta := pseg.Info.SegmentID
	for _, entry := range pseg.ASEntries {
		sigma := binary.BigEndian.Uint16(entry.HopEntry.HopField.MAC[:2])
		beta = beta ^ sigma
	}
	return beta
}
