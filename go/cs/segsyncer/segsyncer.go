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
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/go/cs/handlers"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet/addrutil"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

var _ periodic.Task = (*SegSyncer)(nil)

var (
	errPathDB   = serrors.New("pathdb error")
	errRevcache = serrors.New("revcache error")
	errNoPaths  = serrors.New("no paths")
	errNet      = serrors.New("network error")
)

type pather interface {
	GetPath(svc addr.HostSVC, ps *seg.PathSegment) (net.Addr, error)
}

type SegSyncer struct {
	latestUpdate *time.Time
	pathDB       pathdb.PathDB
	revCache     revcache.RevCache
	msger        infra.Messenger
	dstIA        addr.IA
	localIA      addr.IA
	pather       pather
	repErrCnt    int
}

func StartAll(args handlers.HandlerArgs, msger infra.Messenger) ([]*periodic.Runner, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	coreASes, err := args.ASInspector.ByAttributes(ctx, args.IA.I, trust.Core)
	if err != nil {
		return nil, common.NewBasicError("Failed to get local core ASes", err)
	}

	var pather pather = addrutil.LegacyPather{TopoProvider: args.TopoProvider}
	if args.HeaderV2 {
		pather = addrutil.Pather{
			UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
				return args.TopoProvider.Get().UnderlayNextHop2(common.IFIDType(ifID))
			},
		}
	}

	segSyncers := make([]*periodic.Runner, 0, len(coreASes)-1)
	for _, coreAS := range coreASes {
		if coreAS.Equal(args.IA) {
			continue
		}
		syncer := &SegSyncer{
			pathDB:   args.PathDB,
			revCache: args.RevCache,
			msger:    msger,
			dstIA:    coreAS,
			localIA:  args.IA,
			pather:   pather,
		}
		// TODO(lukedirtwalker): either log or add metric to indicate
		// if task takes longer than ticker often.
		segSyncers = append(segSyncers,
			periodic.Start(syncer, time.Second, 3*time.Second))
	}
	return segSyncers, nil
}

func (s *SegSyncer) Name() string {
	return fmt.Sprintf("ps_segsyncer_segSyncer_%s", s.dstIA)
}

func (s *SegSyncer) Run(ctx context.Context) {
	// TODO(lukedirtwalker): handle too many errors in s.repErrCnt.
	labels := metrics.SyncPushLabels{
		Result: metrics.ErrInternal,
		Dst:    s.dstIA,
	}
	logger := log.FromCtx(ctx)
	cPs, err := s.getDstAddr(ctx)
	if err != nil {
		logger.Error("[segsyncer.SegSyncer] Failed to find path to remote",
			"dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		metrics.Sync.Pushes(labels.WithResult(errToMetricsLabel(err))).Inc()
		return
	}
	cnt, err := s.runInternal(ctx, cPs)
	if err != nil {
		logger.Error("[segsyncer.SegSyncer] Failed to send segSync",
			"dstIA", s.dstIA, "err", err)
		s.repErrCnt++
		metrics.Sync.Pushes(labels.WithResult(errToMetricsLabel(err))).Inc()
		return
	}
	if cnt > 0 {
		logger.Debug("[segsyncer.SegSyncer] Sent down segments",
			"dstIA", s.dstIA, "cnt", cnt)
	}
	metrics.Sync.Pushes(labels.WithResult(metrics.OkSuccess)).Inc()
	s.repErrCnt = 0
}

func (s *SegSyncer) getDstAddr(ctx context.Context) (net.Addr, error) {
	coreSegs, err := s.fetchCoreSegsFromDB(ctx)
	if err != nil {
		return nil, serrors.WrapStr("failed to get core segs", err)
	}
	if len(coreSegs) < 1 {
		return nil, serrors.Wrap(errNoPaths, serrors.New("No core segments found!"))
	}
	var cPs net.Addr
	// select a seg to reach the dst
	for _, ps := range coreSegs {
		cPs, err = s.pather.GetPath(addr.SvcPS, ps)
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
		return nil, serrors.Wrap(errPathDB, err)
	}
	segs := query.Results(res).Segs()
	_, err = segs.FilterSegsErr(func(ps *seg.PathSegment) (bool, error) {
		return revcache.NoRevokedHopIntf(ctx, s.revCache, ps)
	})
	if err != nil {
		return nil, serrors.WrapStr("failed to filter segments",
			serrors.Wrap(errRevcache, err))
	}
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
		return 0, serrors.Wrap(errPathDB, err)
	}
	if len(queryResult) == 0 {
		return 0, nil
	}
	msgs, err := s.createMessages(ctx, queryResult)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, msgT := range msgs {
		err := s.msger.SendSegSync(ctx, msgT.msg, cPs, messenger.NextId())
		if err != nil {
			return sent, serrors.Wrap(errNet, err)
		}
		s.latestUpdate = &msgT.latestUpdate
		sent += len(msgT.msg.SegRecs.Recs)
	}
	return sent, nil
}

// FIXME(lukedirtwalker): Sending a message per segment is quite a big overhead.
// Depending on the underlying transport we could send all segments in a single message.
// We should detect the transport and then split messages depending on the transport layer.
func (s *SegSyncer) createMessages(ctx context.Context,
	qrs []*query.Result) ([]*msgWithTimestamp, error) {

	msgs := make([]*msgWithTimestamp, 0, len(qrs))
	for _, qr := range qrs {
		revs, err := revcache.RelevantRevInfos(ctx, s.revCache, []*seg.PathSegment{qr.Seg})
		if err != nil {
			return nil, serrors.Wrap(errRevcache, err)
		}
		msg := &path_mgmt.SegSync{
			SegRecs: &path_mgmt.SegRecs{
				Recs:      []*seg.Meta{seg.NewMeta(qr.Seg, proto.PathSegType_down)},
				SRevInfos: revs,
			},
		}
		msgs = append(msgs, &msgWithTimestamp{
			msg:          msg,
			latestUpdate: qr.LastUpdate,
		})
	}
	return msgs, nil
}

func errToMetricsLabel(err error) string {
	switch {
	case serrors.IsTimeout(err):
		return metrics.ErrTimeout
	case errors.Is(err, errPathDB):
		return metrics.ErrDB
	case errors.Is(err, errRevcache):
		return metrics.ErrDB
	case errors.Is(err, errNoPaths):
		return metrics.ErrNoPath
	case errors.Is(err, errNet):
		return metrics.ErrNetwork
	default:
		return metrics.ErrNotClassified
	}
}

// msgWithTimestamp is a SegSync message
// with the latest lastUpdate timestamp of the segments in the message.
type msgWithTimestamp struct {
	msg          *path_mgmt.SegSync
	latestUpdate time.Time
}
