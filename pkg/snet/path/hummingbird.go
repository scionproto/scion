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
	"sync"
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
	DstIA addr.IA        // Destination IA of the path.
	Dec   *dphum.Decoded // The Hummingbird path.
	Hops  []*FlyoverData // len(Hops) == len(Dec.Hopfields). Hops[i]==nil iff no flyover at i.
	Now   time.Time      // The current time.
	MinBW uint16         // The minimum required bandwidth for the flyovers.

	counter uint32 // duplicate detection counter
}

var _ snet.DataplanePath = (*Reservation)(nil)

// NewReservation builds a new Hummingbird Reservation based on the destination IA and the
// options passed.
func NewReservation(opts ...ReservationModFcn) (*Reservation, error) {
	r := &Reservation{
		Now: time.Now(),
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

	return r, nil
}

// SetPath sets the path into the passed-by-pointer scion headers.
// When called, the scion layer has its fields (e.g. payload length, src IA, etc.) already set up.
func (r Reservation) SetPath(s *slayers.SCION) error {
	dec := r.DeriveDataPlanePath(s.PayloadLen, r.Now)
	s.Path, s.PathType = dec, dec.Type()
	return nil
}

// DeriveDataPlanePath sets pathmeta timestamps and increments duplicate detection counter and
// updates MACs of all flyoverfields.
func (r Reservation) DeriveDataPlanePath(
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
		if h == nil {
			continue
		}
		hf := &r.Dec.HopFields[i]
		hf.ResStartTime = uint16(secs - h.StartTime)
		flyovermac := hummingbird.FullFlyoverMac(
			h.Ak[:],
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
func WithNow(now time.Time) ReservationModFcn {
	return func(r *Reservation) error {
		r.Now = now
		return nil
	}
}

// WithMinBW modifies the minimum bandwidth required when filtering flyovers at the time of
// reservation creation.
func WithMinBW(bw uint16) ReservationModFcn {
	return func(r *Reservation) error {
		r.MinBW = bw
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

// func WithHummingbirdPath(p *hummingbird.Decoded, flyoverData []*FlyoverData) ReservationModFcn {
// 	return func(r *Reservation) error {
// 		r.Dec = p
// 		r.Hops = flyoverData
// 		return nil
// 	}
// }

// // WithScionDecoded builds a Reservation from a SCION decoded path and the sequence of
// // flyover data. The length of flyovers must be the same as the number of hops in the scion path.
// func WithScionDecoded(p *scion.Decoded, flyovers []*FlyoverData) ReservationModFcn {
// 	return func(r *Reservation) error {
// 		r.Dec = &dphum.Decoded{}
// 		r.Dec.ConvertFromScionDecoded(p)

// 		// Create as many hops as non nil flyovers.
// 		for i, flyover := range flyovers {
// 			if flyover == nil {
// 				continue
// 			}
// 			r.SetFlyover(uint8(i), flyover)
// 		}
// 		return nil
// 	}
// }

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
		r.Hops = make([]*FlyoverData, len(r.Dec.HopFields))

		// We use the path metadata to get the IAs and interface ID sequence from it.
		// This sequence of interfaces does not include the crossover interfaces in the core ASes.
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
			r.SetFlyover(hfIndices[i], consumeFlyover(flyoverMap, baseHop))
		}

		return nil
	}
}

func consumeFlyover(flyoverMap FlyoverMap, baseHop BaseHop) *FlyoverData {
	if flyover, ok := flyoverMap[baseHop]; ok {
		flyover.IsFlyover = true
		delete(flyoverMap, baseHop)
		return flyover
	}
	return &FlyoverData{
		BaseHop:   baseHop,
		IsFlyover: false,
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

type FlyoverData struct {
	BaseHop

	IsFlyover bool     // If false, the rest of the fields in this struct are moot.
	ResID     uint32   // Unique per AS.
	Ak        [16]byte // Authentication key.
	Bw        uint16
	StartTime uint32 // Unix timestamp for the start of the reservation.
	Duration  uint16 // Duration of the reservation in seconds.
}

func (r *Reservation) SetFlyover(
	hfIdx uint8,
	flyover *FlyoverData,
) {
	r.Hops[hfIdx] = flyover
	if !flyover.IsFlyover {
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

	hf.Bw = flyover.Bw
	hf.Duration = flyover.Duration
	hf.ResID = flyover.ResID
}

// FlyoverMap is a map between a flyover <IA,ingress,egress> and its corresponding data.
type FlyoverMap map[BaseHop]*FlyoverData

func FlyoversToMap(flyovers []*FlyoverData) FlyoverMap {
	ret := make(FlyoverMap)
	for _, flyover := range flyovers {
		k := BaseHop{
			IA:      flyover.IA,
			Ingress: flyover.Ingress,
			Egress:  flyover.Egress,
		}
		ret[k] = flyover
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

// GetFlyoversForPath returns a FlyoverMap with all returned flyovers for the given path.
// This function will query paths to on-path ASes and perform a redemption to all of them.
// deleteme the startTime should not be a parameter of this call, but a field in FlyoverData.
func GetFlyoversForPath(p snet.Path, startTime uint32) (FlyoverMap, error) {
	// Get the sequence of ingress->egress interfaces for each on-path AS.
	// Use p.Metadata().Interfaces for this. Include the initial 0->egress for the source AS,
	// and the final ingress->0 for the destination AS.
	interfaces := p.Metadata().Interfaces
	if len(interfaces) == 0 {
		return FlyoverMap{}, nil
	}
	baseHops := InterfacesToBaseHops(interfaces)
	return getFlyoversForHops(baseHops, startTime)
}

func getFlyoversForHops(baseHops []BaseHop, startTime uint32) (FlyoverMap, error) {
	// For each found triplet <AS,ingress,egress> call redeemFlyover and store the result.
	redeemed := make([]*FlyoverData, len(baseHops))
	var wg sync.WaitGroup
	wg.Add(len(baseHops))
	for i := range baseHops {
		go func(i int) {
			defer wg.Done()
			redeemed[i] = redeemFlyover(baseHops[i], startTime)
		}(i)
	}
	wg.Wait()

	flyovers := make(FlyoverMap, len(baseHops))
	for i, baseHop := range baseHops {
		flyovers[baseHop] = redeemed[i]
	}

	return flyovers, nil
}

// redeemFlyover mocks the redemption of a flyover for a given AS, ingress, and egress interfaces.
// The real function will require a daemon.Connector to find a path to the given AS, or the path
// to the given AS.
func redeemFlyover(baseHop BaseHop, startTime uint32) *FlyoverData {
	return &FlyoverData{
		BaseHop:   baseHop,
		IsFlyover: true,
		ResID:     1,
		StartTime: startTime,
		Duration:  10,
		Bw:        64,
		Ak:        [16]byte{},
	}
}
