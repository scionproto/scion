// Copyright 2026 ETH Zurich
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

package path

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

// Reservation is the snet path for a Reservation path type.
// When creating a packet with a Reservation path, the flyover fields must contain the MAC that
// was computed using the correct payload size.
// This path represents a possibly partially reserved path, with zero or more flyovers.
type Reservation struct {
	Now      func() time.Time   // The current time.
	DstIA    addr.IA            // Destination IA of the path.
	Dec      *dphum.Decoded     // The Hummingbird path.
	metadata *snet.PathMetadata // Set at construction time.
	Hops     []*Hop             // Same length as `Dec`. Hops[i]==nil iff no hop at i (eg. xover hop).

	counter uint32 // duplicate detection counter
}

var _ snet.DataplanePath = (*Reservation)(nil)

// NewReservation builds a new Hummingbird Reservation based on the destination IA and the
// options passed.
func NewReservation(opts ...ReservationModFcn) (*Reservation, error) {
	r := &Reservation{
		Now: time.Now,
		Dec: &dphum.Decoded{},
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(r); err != nil {
			return nil, err
		}
	}

	if len(r.Hops) != len(r.Dec.HopFields) {
		return nil, fmt.Errorf("wrong number of flyover hops %d, expected %d from path",
			len(r.Hops), len(r.Dec.HopFields))
	}

	if r.DstIA == 0 {
		return nil, serrors.New("unset destination IA")
	}

	if r.metadata == nil {
		return nil, serrors.New("missing path metadata")
	}

	return r, nil
}

// SetPath sets the path into the passed-by-pointer scion headers.
// When called, the scion layer has its fields (e.g. payload length, src IA, etc.) already set up.
func (r Reservation) SetPath(s *slayers.SCION) error {
	// We need to have a path set in the slayers.SCION to compute its full packet length,
	// since r.Dec and the derived dataplane path have the same length in bytes,
	// use the decoded Hummingbird path initially before deriving the correct dataplane path.
	s.Path, s.PathType = r.Dec, r.Dec.Type()
	dec := r.deriveDataPlanePath(s.PacketLen(), r.Now())
	// Now set the correct dataplane path in the SCION layer.
	s.Path = dec
	return nil
}

// DeriveDataPlanePath sets pathmeta timestamps and increments duplicate detection counter and
// updates MACs of all flyoverfields using the full SCION packet length.
func (r Reservation) deriveDataPlanePath(
	pktLen uint16,
	timeStamp time.Time,
) *dphum.Decoded {

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1000) << 22
	millis |= r.counter
	r.Dec.Base.PathMeta.BaseTS = secs
	r.Dec.Base.PathMeta.HighResTS = millis
	// increment counter for next packet
	r.counter++
	r.counter %= 1 << 22

	// compute Macs for Flyovers
	var byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	var xkbuffer [hummingbird.XkBufferSize]uint32
	for i, h := range r.Hops {
		// Check if hop is xover (no hop) or non flyover (just best effort)
		if h == nil || h.Flyover == nil {
			continue
		}
		f := h.Flyover
		hf := &r.Dec.HopFields[i]
		hf.ResStartTime = uint16(secs - f.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(
			f.Ak[:],
			r.DstIA,
			pktLen,
			hf.ResStartTime,
			millis,
			byteBuffer[:],
			xkbuffer[:],
		)

		binary.BigEndian.PutUint32(hf.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(hf.HopField.Mac[:4]))
		binary.BigEndian.PutUint16(hf.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(hf.HopField.Mac[4:]))
	}
	return r.Dec
}

// ReservationModFcn is a options setting function for a reservation.
type ReservationModFcn func(*Reservation) error

// WithNow modifies the current point in time for this reservation. It is useful to filter
// the different flyovers that can be passed to WithScionPath.
func WithNow(now func() time.Time) ReservationModFcn {
	return func(r *Reservation) error {
		r.Now = now
		return nil
	}
}

// WithDstIA changes the destination IA of the reservation.
func WithDstIA(dstIA addr.IA) ReservationModFcn {
	return func(r *Reservation) error {
		r.DstIA = dstIA
		return nil
	}
}

// WithScionPath allows to build a Reservation based on the SCION path and flyovers passed as
// arguments. If no flyover is found for a hop, that hop will not have priority.
// The flyover map is modified by removing those flyovers that were used during the reservation.
func WithScionPath(p snet.Path, flyoverMap FlyoverMap) ReservationModFcn {
	return func(r *Reservation) error {
		switch p := p.Dataplane().(type) {
		case SCION:
			scion := &scion.Decoded{}
			if err := scion.DecodeFromBytes(p.Raw); err != nil {
				return serrors.Join(err, serrors.New("failed to Prepare Hummingbird Path"))
			}
			r.Dec = &hummingbird.Decoded{}
			r.Dec.ConvertFromScionDecoded(scion)
		default:
			return serrors.New("Unsupported path type")
		}
		// Extend the number of hops to that of the path.
		r.Hops = make([]*Hop, len(r.Dec.HopFields))

		// We use the path metadata to get the IAs and interface ID sequence from it.
		r.metadata = p.Metadata()
		interfaces := p.Metadata().Interfaces
		baseHops := InterfacesToBaseHops(interfaces)

		// Set the destination IA from the path metadata:
		r.DstIA = baseHops[len(baseHops)-1].IA

		hfIndices := reservationHopFieldIndicesForFlyovers(r.Dec)
		if len(hfIndices) != len(baseHops) {
			return serrors.New("inconsistent path metadata to hop-field mapping",
				"base_hops", len(baseHops), "hop_fields", len(hfIndices))
		}
		for i, baseHop := range baseHops {
			r.SetHopAndFlyover(hfIndices[i], consumeFlyover(flyoverMap, baseHop))
		}

		return nil
	}
}

func (r *Reservation) SetHopAndFlyover(
	hfIdx uint8,
	hop *Hop,
) {
	r.Hops[hfIdx] = hop
	if hop.Flyover == nil {
		return
	}

	// Find the hop field from its index.
	hf := &r.Dec.HopFields[hfIdx]

	if !hf.Flyover {
		// Because we are setting a plain hop field as a flyover, it will use two more lines.
		r.Dec.NumLines += 2
		r.Dec.PathMeta.SegLen[r.Dec.InfIndexForHFIndex(hfIdx)] += 2
		hf.Flyover = true
	}

	hf.Bw = hop.Flyover.Bw
	hf.Duration = hop.Flyover.Duration
	hf.ResID = hop.Flyover.ResID
}

func consumeFlyover(flyoverMap FlyoverMap, baseHop BaseHop) *Hop {
	flyover, ok := flyoverMap[baseHop]
	if ok {
		delete(flyoverMap, baseHop)
	}
	return &Hop{
		BaseHop: baseHop,
		Flyover: flyover,
	}
}

// reservationHopFieldIndicesForFlyovers returns the hop field indices in the Hummingbird path
// where flyovers would be written.
// I.e., Hummingbird requires its crossover hop between segments seg1->seg2
// to contain the flyover at the first hop, which is the last hop of seg1. Not all hop fields can
// contain flyovers.
func reservationHopFieldIndicesForFlyovers(dec *hummingbird.Decoded) []uint8 {
	indices := make([]uint8, 0, len(dec.HopFields))
	if dec.NumINF == 0 {
		return indices
	}

	segmentStart := 0

	// Segment 0: include all hops.
	hopCount := int(dec.Base.PathMeta.SegLen[0]) / hummingbird.HopLines
	for hopInSegment := 0; hopInSegment < hopCount; hopInSegment++ {
		indices = append(indices, uint8(segmentStart+hopInSegment))
	}
	segmentStart += hopCount

	// Remaining segments: skip the first hop in each segment.
	for segIdx := 1; segIdx < dec.NumINF; segIdx++ {
		hopCount = int(dec.Base.PathMeta.SegLen[segIdx]) / hummingbird.HopLines
		for hopInSegment := 1; hopInSegment < hopCount; hopInSegment++ {
			indices = append(indices, uint8(segmentStart+hopInSegment))
		}
		segmentStart += hopCount
	}
	return indices
}

// BaseHop describes a pair of Ingress and Egress interfaces in a specific AS
type BaseHop struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}

type Hop struct {
	BaseHop
	Flyover *FlyoverData // nil if this hop is not reserved (just best effort)
}

type FlyoverData struct {
	ResID     uint32   // Unique per AS.
	Ak        [16]byte // Authentication key.
	Bw        uint16
	StartTime uint32 // Unix timestamp for the start of the reservation.
	Duration  uint16 // Duration of the reservation in seconds.
}

// FlyoverMap is a map between a flyover <IA,ingress,egress> and its corresponding data.
type FlyoverMap map[BaseHop]*FlyoverData

func FlyoversToMap(hops []*Hop) FlyoverMap {
	ret := make(FlyoverMap)
	for _, hop := range hops {
		k := hop.BaseHop
		ret[k] = hop.Flyover
	}
	return ret
}

// InterfacesToBaseHops maps path metadata interfaces to per-AS ingress/egress hop tuples.
func InterfacesToBaseHops(ifaces []snet.PathInterface) []BaseHop {
	if len(ifaces) == 0 {
		return nil
	}
	baseHops := make([]BaseHop, 0, len(ifaces)/2+1)
	baseHops = append(baseHops, BaseHop{
		IA:      ifaces[0].IA,
		Ingress: 0,
		Egress:  uint16(ifaces[0].ID),
	})

	for i := 1; i < len(ifaces); i += 2 {
		egress := uint16(0)
		if i+1 < len(ifaces) {
			egress = uint16(ifaces[i+1].ID)
		}
		baseHops = append(baseHops, BaseHop{
			IA:      ifaces[i].IA,
			Ingress: uint16(ifaces[i].ID),
			Egress:  egress,
		})
	}
	return baseHops
}
