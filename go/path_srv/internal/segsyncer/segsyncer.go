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

package segsyncer

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/path_srv/internal/addrutil"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/path_srv/internal/periodic"
	"github.com/scionproto/scion/go/path_srv/internal/segutil"
	"github.com/scionproto/scion/go/proto"
)

var requestID messenger.Counter

var _ periodic.Task = (*SegSyncer)(nil)

type SegSyncer struct {
	lastSync  time.Time
	pathDB    pathdb.PathDB
	revCache  revcache.RevCache
	topology  *topology.Topo
	msger     infra.Messenger
	dstIA     addr.IA
	localIA   addr.IA
	repErrCnt int
}

func StartAll(args handlers.HandlerArgs, msger infra.Messenger) ([]*periodic.Runner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	trc, err := args.TrustStore.GetTRC(ctx, args.Topology.ISD_AS.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Failed to get local TRC", err)
	}
	segSyncers := make([]*periodic.Runner, 0, len(trc.CoreASes)-1)
	for coreAS := range trc.CoreASes {
		if coreAS.Eq(args.Topology.ISD_AS) {
			continue
		}
		syncer := &SegSyncer{
			lastSync: time.Now().Add(-5 * time.Second),
			pathDB:   args.PathDB,
			revCache: args.RevCache,
			topology: args.Topology,
			msger:    msger,
			dstIA:    coreAS,
			localIA:  args.Topology.ISD_AS,
		}
		segSyncers = append(segSyncers, periodic.StartPeriodicTask(syncer,
			time.NewTicker(time.Second), 900*time.Millisecond))

	}
	return segSyncers, nil
}

func (s *SegSyncer) Run(ctx context.Context) {
	start := time.Now()
	// TODO(lukedirtwalker): handle too many errors in s.repErrCnt.
	cPs, err := s.getDstAddr(ctx)
	if err != nil {
		log.Error("[segsyncer] Failed to find path to remote", "dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		return
	}
	cnt, err := s.runInternal(ctx, cPs)
	if err != nil {
		log.Error("[segsyncer] Failed to send segSync", "dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		return
	}
	if cnt > 0 {
		log.Debug("[segsyncer] Sent down segments", "dstIA", s.dstIA, "cnt", cnt)
	}
	s.repErrCnt = 0
	s.lastSync = start
}

func (s *SegSyncer) getDstAddr(ctx context.Context) (net.Addr, error) {
	coreSegs, err := s.fetchCoreSegsFromDB(ctx)
	if err != nil {
		return nil, common.NewBasicError("Failed to get core segs", err)
	}
	if len(coreSegs) < 1 {
		return nil, common.NewBasicError("No core segments found!", nil)
	}
	var cPs net.Addr
	// select a seg to reach the dst
	for _, ps := range coreSegs {
		cPs, err = addrutil.GetPath(addr.SvcPS, ps, ps.FirstIA(), s.topology)
		if err == nil {
			return cPs, nil
		}
	}
	return nil, err
}

func (s *SegSyncer) fetchCoreSegsFromDB(ctx context.Context) ([]*seg.PathSegment, error) {
	params := &query.Params{
		SegTypes: []proto.PathSegType{proto.PathSegType_core},
		StartsAt: []addr.IA{s.dstIA},
		EndsAt:   []addr.IA{s.localIA},
	}
	res, err := s.pathDB.Get(ctx, params)
	if err != nil {
		return nil, err
	}
	segs := query.Results(res).Segs()
	segs.FilterSegs(func(ps *seg.PathSegment) bool {
		return segutil.NoRevokedHopIntf(s.revCache, ps)
	})
	return segs, nil
}

func (s *SegSyncer) runInternal(ctx context.Context, cPs net.Addr) (int, error) {
	q := &query.Params{
		SegTypes:      []proto.PathSegType{proto.PathSegType_down},
		StartsAt:      []addr.IA{s.localIA},
		MinLastUpdate: &s.lastSync,
	}
	queryResult, err := s.pathDB.Get(ctx, q)
	if err != nil {
		return 0, err
	}
	if len(queryResult) == 0 {
		return 0, nil
	}
	segsToSync := query.Results(queryResult).Segs()
	segSync := &path_mgmt.SegSync{
		&path_mgmt.SegRecs{
			Recs:      wrapSegs(segsToSync),
			SRevInfos: segutil.RelevantRevInfos(s.revCache, segsToSync),
		},
	}
	return len(segsToSync), s.msger.SendSegSync(ctx, segSync, cPs, requestID.Next())
}

func wrapSegs(segs []*seg.PathSegment) []*seg.Meta {
	wSegs := make([]*seg.Meta, 0, len(segs))
	for _, s := range segs {
		wSegs = append(wSegs, &seg.Meta{
			Type:    proto.PathSegType_down,
			Segment: s,
		})
	}
	return wSegs
}
