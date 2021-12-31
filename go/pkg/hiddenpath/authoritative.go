// Copyright 2020 Anapaya Systems
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

package hiddenpath

import (
	"context"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
)

// SegmentRequest is a request for hidden segments.
type SegmentRequest struct {
	// GroupIDs are the hidden path group IDs for which the segments are
	// requested.
	GroupIDs []GroupID
	// DstIA is the destination ISD-AS of the segments that are requested.
	DstIA addr.IA
	// Peer is ISD-AS of the requesting peer.
	Peer addr.IA
}

// AuthoritativeServer serves segments from the database.
type AuthoritativeServer struct {
	// Groups is the current set of groups.
	Groups map[GroupID]*Group
	// DB is used to read hidden segments.
	DB Store
	// LocalIA is the ISD-AS this server is run in.
	LocalIA addr.IA
}

// Segments returns the segments for the request or errors out if there was an
// error.
func (s AuthoritativeServer) Segments(ctx context.Context,
	req SegmentRequest) ([]*seg.Meta, error) {

	if len(req.GroupIDs) == 0 {
		return nil, serrors.New("no group IDs provided")
	}
	for _, id := range req.GroupIDs {
		group, ok := s.Groups[id]
		if !ok {
			return nil, serrors.New("request for unknown group", "group_id", id)
		}
		if !canRead(req.Peer, group) {
			return nil, serrors.New("not allowed to read group", "group_id", id)
		}
		if !isAuthoritative(s.LocalIA, group) {
			return nil, serrors.New("not authoritative for group", "group_id", id)
		}
	}
	segs, err := s.DB.Get(ctx, req.DstIA, req.GroupIDs)
	if err != nil {
		return nil, err
	}
	return segs, nil
}

func canRead(peer addr.IA, group *Group) bool {
	owner := group.Owner.Equal(peer)
	_, registry := group.Registries[peer]
	_, writer := group.Writers[peer]
	_, reader := group.Readers[peer]
	return owner || registry || writer || reader
}

func isAuthoritative(localIA addr.IA, group *Group) bool {
	_, auth := group.Registries[localIA]
	return auth
}
