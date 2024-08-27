// Copyright 2017 ETH Zurich
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

// This file contains the Go representation of a hop entry in a AS entry

package segment

import (
	"math"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slayers/path"
)

type HopEntry struct {
	// HopField contains the necessary information to create a data-plane hop.
	HopField HopField
	// IngressMTU is the MTU on the ingress link.
	IngressMTU int
}

func hopEntryFromPB(pb *cppb.HopEntry) (HopEntry, error) {
	if pb == nil {
		return HopEntry{}, serrors.New("nil hop entry")
	}
	if pb.HopField == nil {
		return HopEntry{}, serrors.New("hop field is nil")
	}
	if pb.IngressMtu > math.MaxInt32 {
		return HopEntry{}, serrors.New("MTU too big", "mtu", pb.IngressMtu)
	}
	hop, err := hopFieldFromPB(pb.HopField)
	if err != nil {
		return HopEntry{}, serrors.Wrap("parsing hop field", err)
	}
	return HopEntry{
		HopField:   hop,
		IngressMTU: int(pb.IngressMtu),
	}, nil
}

type PeerEntry struct {
	// HopField contains the necessary information to create a data-plane hop.
	HopField HopField
	// Peer is the ISD-AS of the peering AS.
	Peer addr.IA
	// PeerInterface is the interface ID of the peering link on the remote
	// peering AS side.
	PeerInterface uint16
	// PeerMTU is the MTU on the peering link.
	PeerMTU int
}

func peerEntryFromPB(pb *cppb.PeerEntry) (PeerEntry, error) {
	if pb == nil {
		return PeerEntry{}, serrors.New("nil peer entry")
	}
	if pb.HopField == nil {
		return PeerEntry{}, serrors.New("hop field is nil")
	}
	if ia := addr.IA(pb.PeerIsdAs); ia.IsWildcard() {
		return PeerEntry{}, serrors.New("wildcard peer", "peer_isd_as", ia)
	}
	if pb.PeerInterface > math.MaxUint16 {
		return PeerEntry{}, serrors.New("peer interface exceeds 65535",
			"peer_interface", pb.PeerInterface)
	}
	if pb.PeerMtu > math.MaxInt32 {
		return PeerEntry{}, serrors.New("MTU too big", "mtu", pb.PeerMtu)
	}
	hop, err := hopFieldFromPB(pb.HopField)
	if err != nil {
		return PeerEntry{}, serrors.Wrap("parsing hop field", err)
	}
	return PeerEntry{
		HopField:      hop,
		Peer:          addr.IA(pb.PeerIsdAs),
		PeerInterface: uint16(pb.PeerInterface),
		PeerMTU:       int(pb.PeerMtu),
	}, nil
}

type HopField struct {
	ExpTime     uint8
	ConsIngress uint16
	ConsEgress  uint16
	MAC         [path.MacLen]byte
}

func hopFieldFromPB(pb *cppb.HopField) (HopField, error) {
	if pb.Ingress > math.MaxUint16 {
		return HopField{}, serrors.New("ingress exceeds 65535", "ingress", pb.Ingress)
	}
	if pb.Egress > math.MaxUint16 {
		return HopField{}, serrors.New("egress exceeds 65535", "egress", pb.Egress)
	}
	if pb.ExpTime > math.MaxUint8 {
		return HopField{}, serrors.New("exp_time exceeds 255", "exp_time", pb.ExpTime)
	}
	if len(pb.Mac) != 6 {
		return HopField{}, serrors.New("MAC must be 6 bytes", "len", len(pb.Mac))
	}
	m := [path.MacLen]byte{}
	copy(m[:], pb.Mac)
	return HopField{
		ExpTime:     uint8(pb.ExpTime),
		ConsIngress: uint16(pb.Ingress),
		ConsEgress:  uint16(pb.Egress),
		MAC:         m,
	}, nil
}
