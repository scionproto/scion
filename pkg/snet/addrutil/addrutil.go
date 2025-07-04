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
	"math/rand/v2"
	"net"

	"github.com/scionproto/scion/pkg/addr"
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

// GetPath computes the remote address with a path based on the provided
// segment. If the provided path segment contains discovery information, it will
// use a random available control or discovery service address based on the
// provided service type (addr.SvcCS or addr.SvcDS). If no discovery information
// is available, it will return a SVC address with the destination IA and the
// path's underlay next hop.
func (p Pather) GetPath(svc addr.SVC, ps *seg.PathSegment) (net.Addr, error) {
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
	switch disco := ps.ASEntries[0].Extensions.Discovery; {
	case disco != nil && svc == addr.SvcCS && len(disco.ControlServices) > 0:
		// take any control service address
		return &snet.UDPAddr{
			IA:      ps.FirstIA(),
			Path:    path,
			NextHop: nextHop,
			Host: net.UDPAddrFromAddrPort(
				disco.ControlServices[rand.IntN(len(disco.ControlServices))],
			),
		}, nil
	case disco != nil && svc == addr.SvcDS && len(disco.DiscoveryServices) > 0:
		// take any discovery service address
		return &snet.UDPAddr{
			IA:      ps.FirstIA(),
			Path:    path,
			NextHop: nextHop,
			Host: net.UDPAddrFromAddrPort(
				disco.DiscoveryServices[rand.IntN(len(disco.DiscoveryServices))],
			),
		}, nil
	default:
		return &snet.SVCAddr{
			IA:      ps.FirstIA(),
			Path:    path,
			NextHop: nextHop,
			SVC:     svc,
		}, nil
	}
}

// TopoQuerier can be used to get topology information from the SCION Daemon.
type TopoQuerier interface {
	UnderlayAnycast(ctx context.Context, svc addr.SVC) (*net.UDPAddr, error)
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
func DefaultLocalIP(ctx context.Context, tq TopoQuerier) (net.IP, error) {
	// Choose CS as default routing "target". Using any of the interfaces would also make sense.
	csAddr, err := tq.UnderlayAnycast(ctx, addr.SvcCS)
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

// ExtractDestinationServiceAddress extracts the destination service address
// from the provided path. If the path contains discovery information, it will
// use a random available control or discovery service address based on the
// provided service type (addr.SvcCS or addr.SvcDS). If no discovery information
// is available, it will return a SVC address with the destination IA and the
// path's underlay next hop.
// The caller must ensure that the path is not nil.
func ExtractDestinationServiceAddress(a addr.SVC, path snet.Path) net.Addr {
	if path == nil {
		panic("path is nil")
	}

	destination := path.Destination()
	if metadata := path.Metadata(); metadata != nil {
		disco, hasDiscoveryInfo := metadata.DiscoveryInformation[destination]
		switch {
		case a == addr.SvcCS && hasDiscoveryInfo && len(disco.ControlServices) > 0:
			// Use any control service if available
			cs := disco.ControlServices[rand.IntN(len(disco.ControlServices))]
			ret := &snet.UDPAddr{
				IA:      destination,
				Path:    path.Dataplane(),
				NextHop: path.UnderlayNextHop(),
				Host: &net.UDPAddr{
					IP:   cs.Addr().AsSlice(),
					Port: int(cs.Port()),
				},
			}
			return ret
		case a == addr.SvcDS && hasDiscoveryInfo && len(disco.DiscoveryServices) > 0:
			// Use any discovery service if available
			ds := disco.DiscoveryServices[rand.IntN(len(disco.DiscoveryServices))]
			ret := &snet.UDPAddr{
				IA:      destination,
				Path:    path.Dataplane(),
				NextHop: path.UnderlayNextHop(),
				Host: &net.UDPAddr{
					IP:   ds.Addr().AsSlice(),
					Port: int(ds.Port()),
				},
			}
			return ret
		}
	}
	return &snet.SVCAddr{
		IA:      destination,
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
		SVC:     a,
	}
}
