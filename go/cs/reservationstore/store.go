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

package reservationstore

import (
	"context"
	"math"
	"time"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/cs/reservation/e2e"
	"github.com/scionproto/scion/go/cs/reservation/segment"
	"github.com/scionproto/scion/go/cs/reservationstorage"
	"github.com/scionproto/scion/go/cs/reservationstorage/backend"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/colibri/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// Store is the reservation store.
type Store struct {
	db         backend.DB      // aka reservation map
	capacities base.Capacities // aka capacity matrix
	delta      float64         // fraction of free BW that can be reserved in one request
}

var _ reservationstorage.Store = (*Store)(nil)

// NewStore creates a new reservation store.
func NewStore(db backend.DB) *Store {
	return &Store{
		db: db,
	}
}

// AdmitSegmentReservation receives a setup/renewal request to admit a segment reservation.
// It is expected that this AS is not the reservation initiator.
func (s *Store) AdmitSegmentReservation(ctx context.Context, req *segment.SetupReq) (
	base.MessageWithPath, error) {

	// validate request:
	// DRKey authentication of request (will be left undone for later)
	revPath := req.Path().Copy()
	if err := revPath.Reverse(); err != nil {
		return nil, serrors.WrapStr("while admitting a reservation, cannot reverse path", err,
			"id", req.ID)
	}
	revMetadata, err := base.NewRequestMetadata(revPath)
	if err != nil {
		return nil, serrors.WrapStr("cannot construct metadata for reservation packet", err)
	}
	if req.IndexOfCurrentHop() != len(req.AllocTrail) {
		return nil, serrors.New("inconsistent number of hops",
			"len_alloctrail", len(req.AllocTrail), "hf_count", req.IndexOfCurrentHop())
	}
	failedResponse := &segment.ResponseSetupFailure{
		RequestMetadata: *revMetadata,
		FailedHop:       uint8(len(req.AllocTrail)),
	}
	rsv, err := s.db.GetSegmentRsvFromID(ctx, &req.ID)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot obtain segment reservation", err,
			"id", req.ID)
	}
	tx, err := s.db.BeginTransaction(ctx, nil)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create transaction", err,
			"id", req.ID)
	}
	defer tx.Rollback()

	var index *segment.Index
	if rsv != nil {
		// renewal, ensure index is not used
		index = rsv.Index(req.InfoField.Idx)
		if index != nil {
			return failedResponse, serrors.New("index from setup already in use",
				"idx", req.InfoField.Idx, "id", req.ID)
		}
	} else {
		// setup, create reservation and an index
		rsv = segment.NewReservation()
		rsv.ID = req.ID
		err = tx.NewSegmentRsv(ctx, rsv)
		if err != nil {
			return failedResponse, serrors.WrapStr(
				"unable to create a new segment reservation in db", err,
				"id", req.ID)
		}
	}
	req.Reservation = rsv
	tok := &reservation.Token{InfoField: req.InfoField}
	idx, err := rsv.NewIndexFromToken(tok, req.MinBW, req.MaxBW)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot create index from token", err,
			"id", req.ID)
	}
	index = rsv.Index(idx)

	// checkpath type compatibility with end properties
	if err := rsv.PathEndProps.ValidateWithPathType(rsv.PathType); err != nil {
		return failedResponse, serrors.WrapStr("error validating end props and path type", err,
			"id", req.ID)
	}
	// compute admission max BW
	alloc, err := s.admitSegmentRsv(ctx, req)
	if err != nil {
		// not admitted
		return failedResponse, err
	}
	// admitted; the request contains already the value inside the "allocation beads" of the rsv
	index.AllocBW = alloc
	err = tx.PersistSegmentRsv(ctx, rsv)
	if err != nil {
		return failedResponse, serrors.WrapStr("cannot persist segment reservation", err,
			"id", req.ID)
	}
	if err := tx.Commit(); err != nil {
		return failedResponse, serrors.WrapStr("cannot commit transaction", err,
			"id", req.ID)
	}
	var msg base.MessageWithPath
	if req.IsLastAS() {
		// TODO(juagargi) update token here
		msg = &segment.ResponseSetupSuccess{
			RequestMetadata: *revMetadata,
			Token:           *index.Token,
		}
	} else {
		msg = req
	}
	// TODO(juagargi) refactor function
	return msg, nil
}

// ConfirmSegmentReservation changes the state of an index from temporary to confirmed.
func (s *Store) ConfirmSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// CleanupSegmentReservation deletes an index from a segment reservation.
func (s *Store) CleanupSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// TearDownSegmentReservation removes a whole segment reservation.
func (s *Store) TearDownSegmentReservation(ctx context.Context, id reservation.SegmentID,
	idx reservation.IndexNumber) error {

	return nil
}

// AdmitE2EReservation will atempt to admit an e2e reservation.
func (s *Store) AdmitE2EReservation(ctx context.Context, req e2e.SetupReq) error {
	return nil
}

// CleanupE2EReservation will remove an index from an e2e reservation.
func (s *Store) CleanupE2EReservation(ctx context.Context, id reservation.E2EID,
	idx reservation.IndexNumber) error {

	return nil
}

// DeleteExpiredIndices will just call the DB's method to delete the expired indices.
func (s *Store) DeleteExpiredIndices(ctx context.Context) (int, error) {
	return s.db.DeleteExpiredIndices(ctx, time.Now())
}

func (s *Store) admitSegmentRsv(ctx context.Context, req *segment.SetupReq) (
	reservation.BWCls, error) {

	avail, err := s.availableBW(ctx, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute available bandwidth", err, "segment_id", req.ID)
	}
	ideal, err := s.idealBW(ctx, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute ideal bandwidth", err, "segment_id", req.ID)
	}
	bw := minBW(avail, ideal)

	maxAlloc := reservation.BWClsFromBW(bw)
	if maxAlloc < req.MinBW {
		return 0, serrors.New("admission denied", "maxalloc", maxAlloc, "minbw", req.MinBW,
			"segment_id", req.ID)
	}
	alloc := reservation.MinBWCls(maxAlloc, req.MaxBW)
	bead := reservation.AllocationBead{
		AllocBW: uint8(alloc),
		MaxBW:   uint8(maxAlloc),
	}
	req.AllocTrail = append(req.AllocTrail, bead)
	return alloc, nil
}

func (s *Store) availableBW(ctx context.Context, req *segment.SetupReq) (uint64, error) {
	sameIngress, err := s.db.GetSegmentRsvsFromIFPair(ctx, &req.Ingress, nil)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using ingress", err,
			"ingress", req.Ingress)
	}
	sameEgress, err := s.db.GetSegmentRsvsFromIFPair(ctx, nil, &req.Egress)
	if err != nil {
		return 0, serrors.WrapStr("cannot get reservations using egress", err,
			"egress", req.Egress)
	}
	bwIngress := sumAllRsvButThis(sameIngress, req.ID)
	freeIngress := s.capacities.CapacityIngress(req.Ingress) - bwIngress
	bwEgress := sumAllRsvButThis(sameEgress, req.ID)
	freeEgress := s.capacities.CapacityEgress(req.Egress) - bwEgress
	free := float64(minBW(freeIngress, freeEgress))
	return uint64(free * s.delta), nil
}

func (s *Store) idealBW(ctx context.Context, req *segment.SetupReq) (uint64, error) {
	demsPerSrcRegIngress, err := s.computeTempDemands(ctx, req.Ingress, req)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute temporary demands", err)
	}
	tubeRatio, err := s.tubeRatio(ctx, req, demsPerSrcRegIngress)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute tube ratio", err)
	}
	linkRatio := s.linkRatio(ctx, req, demsPerSrcRegIngress)
	cap := float64(s.capacities.CapacityEgress(req.Egress))
	return uint64(cap * tubeRatio * linkRatio), nil
}

func (s *Store) tubeRatio(ctx context.Context, req *segment.SetupReq, demsPerSrc demPerSource) (
	float64, error) {

	// TODO(juagargi) to avoid calling several times to computeTempDemands, refactor the
	// type holding the results, so that it stores capReqDem per source per ingress interface.
	// InScalFctr and EgScalFctr will be stores independently, per source per interface.
	transitDemand, err := s.transitDemand(ctx, req, req.Ingress, demsPerSrc)
	if err != nil {
		return 0, serrors.WrapStr("cannot compute transit demand", err)
	}
	capIn := s.capacities.CapacityIngress(req.Ingress)
	numerator := minBW(capIn, transitDemand)
	var sum uint64
	for _, in := range s.capacities.IngressInterfaces() {
		demandsForThisIngress, err := s.computeTempDemands(ctx, in, req)
		if err != nil {
			return 0, serrors.WrapStr("cannot compute transit demand", err)
		}
		dem, err := s.transitDemand(ctx, req, in, demandsForThisIngress)
		if err != nil {
			return 0, serrors.WrapStr("cannot compute transit demand", err)
		}
		sum += minBW(s.capacities.CapacityIngress(in), dem)
	}
	return float64(numerator) / float64(sum), nil
}

func (s *Store) linkRatio(ctx context.Context, req *segment.SetupReq,
	demsPerSrc demPerSource) float64 {

	capEg := s.capacities.CapacityEgress(req.Egress)
	demEg := demsPerSrc[req.ID.ASID].eg
	egScalFctr := float64(minBW(capEg, demEg)) / float64(demEg)
	prevBW := float64(req.AllocTrail.MinMax()) // min of maxBW in the trail
	var denom float64
	for id, val := range demsPerSrc {
		egScalFctr := float64(minBW(capEg, val.eg)) / float64(val.eg)
		srcAlloc := float64(req.Reservation.MaxBlockedBW())
		if req.ID.ASID == id {
			srcAlloc += prevBW
		}
		denom += egScalFctr * 1
	}
	return egScalFctr * prevBW / denom
}

// demands represents the demands of a given source.
type demands struct {
	src, in, eg uint64
}

// demsPerSrc is used in the transit demand computation.
type demPerSource map[addr.AS]demands

// computeTempDemands will compute inDem, egDem and srcDem grouped by source, for all sources.
func (s *Store) computeTempDemands(ctx context.Context, ingress common.IFIDType,
	req *segment.SetupReq) (demPerSource, error) {

	// TODO(juagargi) consider adding a call to db to get all srcDem,inDem,egDem grouped by source
	rsvs, err := s.db.GetAllSegmentRsvs(ctx)
	if err != nil {
		return nil, serrors.WrapStr("cannot obtain segment rsvs. from ingress/egress pair", err)
	}
	capIn := s.capacities.CapacityIngress(ingress)
	capEg := s.capacities.CapacityEgress(req.Egress)
	// srcDem, inDem and egDem grouped by source
	demsPerSrc := make(demPerSource)
	for _, rsv := range rsvs {
		var dem uint64 // capReqDem
		if rsv.ID == req.ID {
			dem = min3BW(capIn, capEg, req.MaxBW.ToKBps())
		} else {
			dem = min3BW(capIn, capEg, rsv.MaxRequestedBW())
		}
		bucket := demsPerSrc[rsv.ID.ASID]
		if rsv.Ingress == ingress {
			bucket.in += dem
		} else if rsv.Egress == req.Egress {
			bucket.eg += dem
		}
		if rsv.Ingress == ingress && rsv.Egress == req.Egress {
			bucket.src += dem
		}
		demsPerSrc[rsv.ID.ASID] = bucket
	}
	return demsPerSrc, nil
}

// transitDemand computes the transit demand from ingress to req.Egress. The parameter
// demsPerSrc must hold the inDem, egDem and srcDem of all reservations, grouped by source, and
// for an ingress interface = ingress parameter.
func (s *Store) transitDemand(ctx context.Context, req *segment.SetupReq, ingress common.IFIDType,
	demsPerSrc demPerSource) (
	uint64, error) {

	capIn := s.capacities.CapacityIngress(ingress)
	capEg := s.capacities.CapacityEgress(req.Egress)
	// TODO(juagargi) adjSrcDem is not needed, remove after finishing debugging the admission
	adjSrcDem := make(map[addr.AS]uint64) // every adjSrcDem grouped by source
	for src, dems := range demsPerSrc {
		inScalFctr := float64(minBW(capIn, dems.in)) / float64(dems.in)
		egScalFctr := float64(minBW(capEg, dems.eg)) / float64(dems.eg)
		adjSrcDem[src] = uint64(math.Min(inScalFctr, egScalFctr) * float64(dems.src))
	}
	// now reduce adjSrcDem
	var transitDem uint64
	for _, dem := range adjSrcDem {
		transitDem += dem
	}

	return transitDem, nil
}

func sumAllRsvButThis(rsvs []*segment.Reservation, excludeRsv reservation.SegmentID) uint64 {
	var total uint64
	for _, r := range rsvs {
		if r.ID != excludeRsv {
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
