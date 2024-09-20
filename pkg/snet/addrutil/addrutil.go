// Copyright 2018 Anapaya Systems
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

package addrutil

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather struct {
	NextHopper interface {
		// UnderlayNextHop determines the next hop underlay address for the
		// specified interface id.
		UnderlayNextHop(uint16) *net.UDPAddr
	}
}

// GetPath computes the remote address with a path based on the provided segment.
func (p Pather) GetPath(svc addr.SVC, ps *seg.PathSegment) (*snet.SVCAddr, error) {
	if len(ps.ASEntries) == 0 {
		return nil, serrors.New("empty path")
	}

	beta := ps.Info.SegmentID
	// The hop fields need to be in reversed order.
	hopFields := make([]path.HopField, len(ps.ASEntries))
	for i, entry := range ps.ASEntries {
		hopFields[len(hopFields)-1-i] = path.HopField{
			ConsIngress: entry.HopEntry.HopField.ConsIngress,
			ConsEgress:  entry.HopEntry.HopField.ConsEgress,
			ExpTime:     entry.HopEntry.HopField.ExpTime,
			Mac:         entry.HopEntry.HopField.MAC,
		}
		// the last AS entry is our AS for this we don't need to modify the beta.
		if i < len(ps.ASEntries)-1 {
			beta = beta ^ binary.BigEndian.Uint16(entry.HopEntry.HopField.MAC[:2])
		}
	}

	hops := len(hopFields)
	dec := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF:  0,
				CurrINF: 0,
				SegLen:  [3]uint8{uint8(hops), 0, 0},
			},
			NumHops: hops,
			NumINF:  1,
		},
		InfoFields: []path.InfoField{{
			Timestamp: util.TimeToSecs(ps.Info.Timestamp),
			ConsDir:   false,
			SegID:     beta,
		}},
		HopFields: hopFields,
	}
	path, err := snetpath.NewSCIONFromDecoded(dec)
	if err != nil {
		return nil, serrors.Wrap("serializing path", err)
	}
	ifID := dec.HopFields[0].ConsIngress
	nextHop := p.NextHopper.UnderlayNextHop(ifID)
	if nextHop == nil {
		return nil, serrors.New("first-hop border router not found", "intf_id", ifID)
	}
	return &snet.SVCAddr{
		IA:      ps.FirstIA(),
		Path:    path,
		NextHop: nextHop,
		SVC:     svc,
	}, nil

}

// DefaultLocalIP returns _an_ IP of this host in the local AS.
//
// This returns a sensible but arbitrary local IP. In the general case the
// local IP would depend on the next hop of selected path. This approach will
// not work in more complicated setups where e.g. different network interfaces
// are used to talk to different AS interfaces.
//
// This is a simple workaround for not being able to use wildcard addresses
// with snet. Once available, a wildcard address should be used instead and
// this should be removed.
func DefaultLocalIP(ctx context.Context, sdConn daemon.Connector) (net.IP, error) {
	// Choose CS as default routing "target". Using any of the interfaces would also make sense.
	csAddr, err := daemon.TopoQuerier{Connector: sdConn}.UnderlayAnycast(ctx, addr.SvcCS)
	if err != nil {
		return nil, err
	}
	return ResolveLocal(csAddr.IP)
}

// ResolveLocal returns the local IP address used for traffic destined to dst.
func ResolveLocal(dst net.IP) (net.IP, error) {
	udpAddr := net.UDPAddr{IP: dst, Port: 1}
	udpConn, err := net.DialUDP(udpAddr.Network(), nil, &udpAddr)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	srcIP := udpConn.LocalAddr().(*net.UDPAddr).IP
	return srcIP, nil
}
