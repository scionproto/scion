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
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/path_srv/internal/addrutil"
	"github.com/scionproto/scion/go/path_srv/internal/handlers"
	"github.com/scionproto/scion/go/path_srv/internal/segutil"
	"github.com/scionproto/scion/go/proto"
)

var requestID messenger.Counter

var _ periodic.Task = (*SegSyncer)(nil)

type SegSyncer struct {
	latestUpdate *time.Time
	pathDB       pathdb.PathDB
	revCache     revcache.RevCache
	msger        infra.Messenger
	dstIA        addr.IA
	localIA      addr.IA
	repErrCnt    int
}

func StartAll(args handlers.HandlerArgs, msger infra.Messenger) ([]*periodic.Runner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	trc, err := args.TrustStore.GetTRC(ctx, args.IA.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Failed to get local TRC", err)
	}
	segSyncers := make([]*periodic.Runner, 0, len(trc.CoreASes)-1)
	for coreAS := range trc.CoreASes {
		if coreAS.Eq(args.IA) {
			continue
		}
		syncer := &SegSyncer{
			pathDB:   args.PathDB,
			revCache: args.RevCache,
			msger:    msger,
			dstIA:    coreAS,
			localIA:  args.IA,
		}
		// TODO(lukedirtwalker): either log or add metric to indicate
		// if task takes longer than ticker often.
		segSyncers = append(segSyncers, periodic.StartPeriodicTask(syncer,
			time.NewTicker(time.Second), 3*time.Second))
	}
	return segSyncers, nil
}

func (s *SegSyncer) Run(ctx context.Context) {
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
		cPs, err = addrutil.GetPath(addr.SvcPS, ps, ps.FirstIA(), itopo.GetCurrentTopology())
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
	// Sort by number of hops, i.e. AS entries.
	sort.Slice(segs, func(i, j int) bool {
		return len(segs[i].ASEntries) < len(segs[j].ASEntries)
	})
	return segs, nil
}

func (s *SegSyncer) runInternal(ctx context.Context, cPs net.Addr) (int, error) {
	q := &query.Params{
		SegTypes:      []proto.PathSegType{proto.PathSegType_down},
		StartsAt:      []addr.IA{s.localIA},
		MinLastUpdate: s.latestUpdate,
	}
	queryResult, err := s.pathDB.Get(ctx, q)
	if err != nil {
		return 0, err
	}
	if len(queryResult) == 0 {
		return 0, nil
	}
	msgs := s.createMessages(queryResult)
	sent := 0
	for _, msgT := range msgs {
		err := s.msger.SendSegSync(ctx, msgT.msg, cPs, requestID.Next())
		if err != nil {
			return sent, err
		}
		s.latestUpdate = &msgT.latestUpdate
		sent += len(msgT.msg.SegRecs.Recs)
	}
	return sent, nil
}

// FIXME(lukedirtwalker): Sending a message per segment is quite a big overhead.
// Depending on the underlying transport we could send all segments in a single message.
// We should detect the transport and then split messages depending on the transport layer.
func (s *SegSyncer) createMessages(qrs []*query.Result) []*msgWithTimestamp {
	msgs := make([]*msgWithTimestamp, 0, len(qrs))
	for _, qr := range qrs {
		msg := &path_mgmt.SegSync{
			SegRecs: &path_mgmt.SegRecs{
				Recs:      []*seg.Meta{seg.NewMeta(qr.Seg, proto.PathSegType_down)},
				SRevInfos: segutil.RelevantRevInfos(s.revCache, []*seg.PathSegment{qr.Seg}),
			},
		}
		msgs = append(msgs, &msgWithTimestamp{
			msg:          msg,
			latestUpdate: qr.LastUpdate,
		})
	}
	return msgs
}

// msgWithTimestamp is a SegSync message
// with the latest lastUpdate timestamp of the segments in the message.
type msgWithTimestamp struct {
	msg          *path_mgmt.SegSync
	latestUpdate time.Time
}
