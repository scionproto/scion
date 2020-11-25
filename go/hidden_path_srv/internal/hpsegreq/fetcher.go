// Copyright 2019 ETH Zurich
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

package hpsegreq

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"
	"github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpathdb"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	ErrUnknownGroup = serrors.New("group not known to HPS")
	ErrNotReader    = serrors.New("peer is not a reader of this group")
)

// RPC is a temporary interface to allow code to compile.
// This should be replaced by an interface that is appropriate for gRPC.
type RPC interface {
	GetHPSegs(context.Context, *path_mgmt.HPSegReq, net.Addr) (*path_mgmt.HPSegReply, error)
}

// Fetcher is a fetcher for hidden path segments
type Fetcher interface {
	// Fetch fetches hidden path segments.
	// In case of local HPS the segments are fetched from the database,
	// otherwise segments are requested from a remote HPS
	Fetch(ctx context.Context,
		req *path_mgmt.HPSegReq, peer *snet.UDPAddr) ([]*path_mgmt.HPSegRecs, error)
}

var _ Fetcher = (*DefaultFetcher)(nil)

// DefaultFetcher fetches hidden path segments from database and remote HPS
type DefaultFetcher struct {
	groupInfo *GroupInfo
	msgr      RPC
	db        hiddenpathdb.HiddenPathDB
}

// NewDefaultFetcher creates a new DefaultFetcher
func NewDefaultFetcher(groupInfo *GroupInfo, msgr RPC,
	db hiddenpathdb.HiddenPathDB) *DefaultFetcher {

	return &DefaultFetcher{
		groupInfo: groupInfo,
		msgr:      msgr,
		db:        db,
	}
}

// Fetch fetches the hidden path segments either from DB or from a remote HPS
func (f *DefaultFetcher) Fetch(ctx context.Context,
	req *path_mgmt.HPSegReq, peer *snet.UDPAddr) ([]*path_mgmt.HPSegRecs, error) {

	ids := make([]hiddenpath.GroupId, 0, len(req.GroupIds))
	for _, rawId := range req.GroupIds {
		id := hiddenpath.IdFromMsg(rawId)
		if err := f.checkGroupPermissions(id, peer.IA); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	mapping, err := f.groupInfo.GetRegistryMapping(hiddenpath.GroupIdsToSet(ids...))
	if err != nil {
		return nil, err
	}
	endsAt := req.RawDstIA.IA()
	replyChan := make(chan []*path_mgmt.HPSegRecs, len(mapping))
	for hps, ids := range mapping {
		if hps.Equal(f.groupInfo.LocalIA) {
			go func(ids []hiddenpath.GroupId) {
				defer log.HandlePanic()
				f.fetchDB(ctx, ids, endsAt, replyChan)
			}(ids)
		} else {
			go func(ids []hiddenpath.GroupId, hps addr.IA) {
				defer log.HandlePanic()
				f.fetchRemote(ctx, ids, endsAt, hps, replyChan)
			}(ids, hps)
		}
	}

	recs := []*path_mgmt.HPSegRecs{}
	for i := 0; i < len(mapping); i++ {
		recs = append(recs, <-replyChan...)
	}
	return recs, nil
}

func (f *DefaultFetcher) fetchDB(ctx context.Context, ids []hiddenpath.GroupId,
	endsAt addr.IA, replyChan chan []*path_mgmt.HPSegRecs) {

	// TODO(chaehni): we need to query the DB separately for every GroupId so that we
	// have the mapping from Id to segments. This is not optimal.
	var recs = make([]*path_mgmt.HPSegRecs, 0, len(ids))
	for _, id := range ids {
		params := &hiddenpathdb.Params{
			GroupIds: hiddenpath.GroupIdsToSet(id),
			EndsAt:   endsAt,
		}
		results, err := f.db.Get(ctx, params)
		if err != nil {
			recs = append(recs, &path_mgmt.HPSegRecs{GroupId: id.ToMsg(), Err: err.Error()})
			continue
		}
		segs := make([]*seg.Meta, 0, len(results))
		for _, res := range results {
			segs = append(segs, &seg.Meta{Type: res.Type, Segment: res.Seg})
		}
		recs = append(recs, &path_mgmt.HPSegRecs{GroupId: id.ToMsg(), Recs: segs})
	}
	replyChan <- recs
}

func (f *DefaultFetcher) fetchRemote(ctx context.Context, ids []hiddenpath.GroupId,
	endsAt, remote addr.IA, replyChan chan []*path_mgmt.HPSegRecs) {

	rawIds := make([]*path_mgmt.HPGroupId, 0, len(ids))
	for _, id := range ids {
		rawIds = append(rawIds, id.ToMsg())
	}
	req := &path_mgmt.HPSegReq{
		RawDstIA: endsAt.IAInt(),
		GroupIds: rawIds,
	}
	addr := &snet.SVCAddr{IA: remote, SVC: addr.SvcHPS}
	reply, err := f.msgr.GetHPSegs(ctx, req, addr)
	if err != nil {
		var recs = make([]*path_mgmt.HPSegRecs, 0, len(ids))
		for _, id := range rawIds {
			recs = append(recs, &path_mgmt.HPSegRecs{GroupId: id, Err: err.Error()})
		}
		replyChan <- recs
		return
	}
	replyChan <- reply.Recs
}

func (f *DefaultFetcher) checkGroupPermissions(groupId hiddenpath.GroupId, peer addr.IA) error {
	group, ok := f.groupInfo.Groups[groupId]
	if !ok {
		return ErrUnknownGroup
	}
	if peer != group.Owner && !group.HasReader(peer) {
		return ErrNotReader
	}
	return nil
}
