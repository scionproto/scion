// Copyright 2020 ETH Zurich, Anapaya Systems
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

package impl

import (
	"context"
	"math"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservation/segment/admission"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/serrors"
)

// StatelessAdmission can admit a segment reservation without any state other than the DB.
type StatelessAdmission struct {
	DB         backend.DB
	Capacities base.Capacities // aka capacity matrix
	Delta      float64         // fraction of free BW that can be reserved in one request
}

var _ admission.Admitter = (*StatelessAdmission)(nil)

// AdmitRsv admits a segment reservation. The request will be modified with the allowed and
// maximum bandwidths if they were computed. It can also return an error that must be checked.
func (a *StatelessAdmission) AdmitRsv(ctx context.Context, req *segment.SetupReq) error {
	avail, err := a.availableBW(ctx, req)
	if err != nil {
		return serrors.WrapStr("cannot compute available bandwidth", err, "segment_id", req.ID)
	}
	ideal, err := a.idealBW(ctx, req)
	if err != nil {
		return serrors.WrapStr("cannot compute ideal bandwidth", err, "segment_id", req.ID)
	}
	maxAlloc := reservation.BWClsFromBW(minBW(avail, ideal))
	bead := reservation.AllocationBead{
		AllocBW: reservation.MinBWCls(maxAlloc, req.MaxBW),
		MaxBW:   maxAlloc,
	}
	req.AllocTrail = append(req.AllocTrail, bead)
	if maxAlloc < req.MinBW {
		return serrors.New("admission denied", "maxalloc", maxAlloc, "minbw", req.MinBW,
			"segment_id", req.ID)
	}
	return nil
}

func (a *StatelessAdmission) availableBW(ctx context.Context, req *segment.SetupReq) (
	uint64, error) {

	sameIngress, err := a.DB.GetSegmentRsvsFromIFPair(ctx, &req.Ingress, nil)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using ingress", err,
			"ingress", req.Ingress)
	}
	sameEgress, err := a.DB.GetSegmentRsvsFromIFPair(ctx, nil, &req.Egress)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using egress", err,
			"egress", req.Egress)
	}
	bwIngress := sumMaxBlockedBW(sameIngress, req.ID)
	freeIngress := a.Capacities.CapacityIngress(req.Ingress) - bwIngress
	bwEgress := sumMaxBlockedBW(sameEgress, req.ID)
	freeEgress := a.Capacities.CapacityEgress(req.Egress) - bwEgress
	// `free` excludes the BW from an existing reservation if its ID equals the request's ID
	free := float64(minBW(freeIngress, freeEgress))
	return uint64(free * a.Delta), nil
}

func (a *StatelessAdmission) idealBW(ctx context.Context, req *segment.SetupReq) (uint64, error) {
	demsPerSrcRegIngress, err := a.computeTempDemands(ctx, req.Ingress, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute temporary demands", err)
	}
	tubeRatio, err := a.tubeRatio(ctx, req, demsPerSrcRegIngress)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute tube ratio", err)
	}
	linkRatio, err := a.linkRatio(ctx, req, demsPerSrcRegIngress)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute link ratio", err)
	}
	cap := float64(a.Capacities.CapacityEgress(req.Egress))
	return uint64(cap * tubeRatio * linkRatio), nil
}

func (a *StatelessAdmission) tubeRatio(ctx context.Context, req *segment.SetupReq,
	demsPerSrc demPerSource) (float64, error) {

	// TODO(juagargi) to avoid calling several times to computeTempDemands, refactor the
	// type holding the results, so that it stores capReqDem per source per ingress interface.
	// InScalFctr and EgScalFctr will be stored independently, per source per interface.
	transitDemand, err := a.transitDemand(ctx, req, req.Ingress, demsPerSrc)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute transit demand", err)
	}
	capIn := a.Capacities.CapacityIngress(req.Ingress)
	numerator := minBW(capIn, transitDemand)
	var sum uint64
	for _, in := range a.Capacities.IngressInterfaces() {
		demandsForThisIngress, err := a.computeTempDemands(ctx, in, req)
		if err != nil {
			return 0, serrors.WrapStr("cannot compute transit demand", err)
		}
		dem, err := a.transitDemand(ctx, req, in, demandsForThisIngress)
		if err != nil {
			return 0, serrors.WrapStr("cannot compute transit demand", err)
		}
		sum += minBW(a.Capacities.CapacityIngress(in), dem)
	}
	return float64(numerator) / float64(sum), nil
}

func (a *StatelessAdmission) linkRatio(ctx context.Context, req *segment.SetupReq,
	demsPerSrc demPerSource) (float64, error) {

	capEg := a.Capacities.CapacityEgress(req.Egress)
	demEg := demsPerSrc[req.ID.ASID].eg

	prevBW := req.AllocTrail.MinMax().ToKbps() // min of maxBW in the trail
	var egScalFctr float64
	if demEg != 0 {
		egScalFctr = float64(minBW(capEg, demEg)) / float64(demEg)
	}
	numerator := egScalFctr * float64(prevBW)
	egScalFctrs := make(map[addr.AS]float64)
	for src, dem := range demsPerSrc {
		var egScalFctr float64
		if dem.eg != 0 {
			egScalFctr = float64(minBW(capEg, dem.eg)) / float64(dem.eg)
		}
		egScalFctrs[src] = egScalFctr
	}
	rsvs, err := a.DB.GetAllSegmentRsvs(ctx)
	if err != nil {
		return 0, serrors.WrapStr("cannot list all reservations", err)
	}
	srcAllocPerSrc := make(map[addr.AS]uint64)
	for _, rsv := range rsvs {
		if rsv.ID == req.ID {
			continue
		}
		src := rsv.ID.ASID
		srcAlloc := rsv.MaxBlockedBW()
		srcAllocPerSrc[src] += srcAlloc
	}
	if _, found := srcAllocPerSrc[req.ID.ASID]; !found {
		// add the source of the request, if not already present
		srcAllocPerSrc[req.ID.ASID] = 0 // the value of the srcAlloc itself won't be used
	}
	// TODO(juagargi) after debugging, integrate this loop into the previous one:
	var denom float64
	for src, srcAlloc := range srcAllocPerSrc {
		if src == req.ID.ASID {
			srcAlloc += prevBW
		}
		egScalFctr, found := egScalFctrs[src]
		if !found {
			return 0, serrors.New("cannot compute link ratio, internal error: "+
				"source not found in the egress scale factors", "src", src)
		}
		denom += float64(srcAlloc) * egScalFctr
	}
	return numerator / denom, nil
}

// demands represents the demands for a given source, and a specific ingress-egress interface pair.
// from the admission spec: srcDem, inDem and egDem for a given source.
type demands struct {
	src, in, eg uint64
}

// demsPerSrc is used in the transit demand computation.
type demPerSource map[addr.AS]demands

// computeTempDemands will compute inDem, egDem and srcDem grouped by source, for all sources.
// this is, all cap. requested demands from all reservations, grouped by source, that enter
// the AS at "ingress" and exit at "egress". It also stores all the source demands that enter
// the AS at "ingress", and the source demands that exit the AS at "egress".
func (a *StatelessAdmission) computeTempDemands(ctx context.Context, ingress uint16,
	req *segment.SetupReq) (demPerSource, error) {

	// TODO(juagargi) consider adding a call to db to get all srcDem,inDem,egDem grouped by source
	rsvs, err := a.DB.GetAllSegmentRsvs(ctx)
	if err != nil {
		return nil, serrors.WrapStr("cannot obtain segment rsvs. from ingress/egress pair", err)
	}
	capIn := a.Capacities.CapacityIngress(ingress)
	capEg := a.Capacities.CapacityEgress(req.Egress)
	// srcDem, inDem and egDem grouped by source
	demsPerSrc := make(demPerSource)
	for _, rsv := range rsvs {
		if rsv.ID == req.ID {
			continue
		}
		dem := min3BW(capIn, capEg, rsv.MaxRequestedBW()) // capReqDem in the formulas
		bucket := demsPerSrc[rsv.ID.ASID]
		if rsv.Ingress == ingress {
			bucket.in += dem
		}
		if rsv.Egress == req.Egress {
			bucket.eg += dem
		}
		if rsv.Ingress == ingress && rsv.Egress == req.Egress {
			bucket.src += dem
		}
		demsPerSrc[rsv.ID.ASID] = bucket
	}
	// add the request itself to whatever we have for that source
	bucket := demsPerSrc[req.ID.ASID]
	dem := min3BW(capIn, capEg, req.MaxBW.ToKbps())
	if req.Ingress == ingress {
		bucket.in += dem
	}
	if req.Egress == req.Egress {
		bucket.eg += dem
	}
	if req.Ingress == ingress && req.Egress == req.Egress {
		bucket.src += dem
	}
	demsPerSrc[req.ID.ASID] = bucket

	return demsPerSrc, nil
}

// transitDemand computes the transit demand from ingress to req.Egress. The parameter
// demsPerSrc must hold the inDem, egDem and srcDem of all reservations, grouped by source, and
// for an ingress interface = ingress parameter.
func (a *StatelessAdmission) transitDemand(ctx context.Context, req *segment.SetupReq,
	ingress uint16, demsPerSrc demPerSource) (uint64, error) {

	capIn := a.Capacities.CapacityIngress(ingress)
	capEg := a.Capacities.CapacityEgress(req.Egress)
	// TODO(juagargi) adjSrcDem is not needed, remove after finishing debugging the admission
	adjSrcDem := make(map[addr.AS]uint64) // every adjSrcDem grouped by source
	for src, dems := range demsPerSrc {
		var inScalFctr float64 = 1.
		if dems.in != 0 {
			inScalFctr = float64(minBW(capIn, dems.in)) / float64(dems.in)
		}
		var egScalFctr float64 = 1.
		if dems.eg != 0 {
			egScalFctr = float64(minBW(capEg, dems.eg)) / float64(dems.eg)
		}
		adjSrcDem[src] = uint64(math.Min(inScalFctr, egScalFctr) * float64(dems.src))
	}
	// now reduce adjSrcDem
	var transitDem uint64
	for _, dem := range adjSrcDem {
		transitDem += dem
	}

	return transitDem, nil
}

// sumMaxBlockedBW adds up all the max blocked bandwidth by the reservation, for all reservations,
// iff they don't have the same ID as "excludeThisRsv".
func sumMaxBlockedBW(rsvs []*segment.Reservation, excludeThisRsv reservation.SegmentID) uint64 {
	var total uint64
	for _, r := range rsvs {
		if r.ID != excludeThisRsv {
			total += r.MaxBlockedBW()
		}
	}
	return total
}

func minBW(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func min3BW(a, b, c uint64) uint64 {
	return minBW(minBW(a, b), c)
}
