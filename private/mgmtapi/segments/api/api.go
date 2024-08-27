// Copyright 2021 Anapaya Systems
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

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	seg "github.com/scionproto/scion/pkg/segment"
	api "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/pathdb/query"
)

type SegmentStore interface {
	Get(context.Context, *query.Params) (query.Results, error)
	DeleteSegment(ctx context.Context, partialID string) error
}

type Server struct {
	Segments SegmentStore
}

// GetSegments gets the stored in the PathDB.
func (s *Server) GetSegments(w http.ResponseWriter, r *http.Request, params GetSegmentsParams) {
	q := query.Params{}
	var errs serrors.List
	if params.StartIsdAs != nil {
		if ia, err := addr.ParseIA(*params.StartIsdAs); err == nil {
			q.StartsAt = []addr.IA{ia}
		} else {
			errs = append(errs, serrors.Wrap("invalid start ISD_AS", err))
		}
	}
	if params.EndIsdAs != nil {
		if ia, err := addr.ParseIA(*params.EndIsdAs); err == nil {
			q.EndsAt = []addr.IA{ia}
		} else {
			errs = append(errs, serrors.Wrap("invalid end ISD_AS", err))
		}
	}
	if err := errs.ToError(); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	res, err := s.Segments.Get(r.Context(), &q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	sort.Sort(res)
	rep := make([]*SegmentBrief, 0, len(res))
	for _, segRes := range res {
		rep = append(rep, &SegmentBrief{
			Id:         SegID(segRes.Seg),
			StartIsdAs: segRes.Seg.FirstIA().String(),
			EndIsdAs:   segRes.Seg.LastIA().String(),
			Length:     len(segRes.Seg.ASEntries),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

// GetSegment gets a segments details specified by its ID.
func (s *Server) GetSegment(w http.ResponseWriter, r *http.Request, segmentID SegmentID) {
	id, err := hex.DecodeString(segmentID)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	q := query.Params{SegIDs: [][]byte{id}}
	resp, err := s.Segments.Get(r.Context(), &q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	if len(resp) != 1 {
		Error(w, Problem{
			Detail: api.StringRef(fmt.Sprintf(
				"provided id matched %d segments",
				len(resp),
			)),
			Status: http.StatusBadRequest,
			Title:  "error no segment found",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	segRes := resp[0]
	var hops []Hop
	for i, as := range segRes.Seg.ASEntries {
		if i != 0 {
			hops = append(hops, Hop{
				Interface: int(as.HopEntry.HopField.ConsIngress),
				IsdAs:     as.Local.String(),
			})
		}
		if i != len(segRes.Seg.ASEntries)-1 {
			hops = append(hops, Hop{
				Interface: int(as.HopEntry.HopField.ConsEgress),
				IsdAs:     as.Local.String(),
			})
		}
	}
	rep := Segment{
		Id:          SegID(segRes.Seg),
		Timestamp:   segRes.Seg.Info.Timestamp.UTC(),
		Expiration:  segRes.Seg.MinExpiry().UTC(),
		LastUpdated: segRes.LastUpdate.UTC(),
		Hops:        hops,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(rep); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
}

func (s *Server) DeleteSegment(w http.ResponseWriter, r *http.Request, segmentId SegmentID) {
	if segmentId == "" {
		Error(w, Problem{
			Status: http.StatusBadRequest,
			Title:  "segment ID is required",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	if err := s.Segments.DeleteSegment(r.Context(), segmentId); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to delete segment",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetSegmentBlob gets a segment (specified by its ID) as a pem encoded blob.
func (s *Server) GetSegmentBlob(w http.ResponseWriter, r *http.Request, segmentID SegmentID) {
	w.Header().Set("Content-Type", "application/x-pem-file")

	id, err := hex.DecodeString(segmentID)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusBadRequest,
			Title:  "malformed query parameters",
			Type:   api.StringRef(api.BadRequest),
		})
		return
	}
	q := query.Params{SegIDs: [][]byte{id}}
	resp, err := s.Segments.Get(r.Context(), &q)
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "error getting segments",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	if len(resp) != 1 {
		Error(w, Problem{
			Detail: api.StringRef(
				fmt.Sprintf("found %d segments for the provided segment-id",
					len(resp),
				)),
			Status: http.StatusInternalServerError,
			Title:  "provided segment-id is not unique or does not exist",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	var buf bytes.Buffer
	segRes := resp[0]
	bytes, err := proto.Marshal(seg.PathSegmentToPB(segRes.Seg))
	if err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal segment",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	b := &pem.Block{
		Type:  "PATH SEGMENT",
		Bytes: bytes,
	}
	if err := pem.Encode(&buf, b); err != nil {
		Error(w, Problem{
			Detail: api.StringRef(err.Error()),
			Status: http.StatusInternalServerError,
			Title:  "unable to marshal response",
			Type:   api.StringRef(api.InternalError),
		})
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// SegID makes a hex encoded string of the segment id.
func SegID(s *seg.PathSegment) string { return fmt.Sprintf("%x", s.ID()) }

// Error creates an detailed error response.
func Error(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	// no point in catching error here, there is nothing we can do about it anymore.
	_ = enc.Encode(p)
}
