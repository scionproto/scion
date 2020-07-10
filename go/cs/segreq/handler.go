// Copyright 2019 Anapaya Systems
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

package segreq

import (
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

// Handler handles segment requests.
type Handler struct {
	Fetcher  *segfetcher.Fetcher
	RevCache revcache.RevCache
}

// Handle handles a segment request.
func (h *Handler) Handle(request *infra.Request) *infra.HandlerResult {
	ctx := request.Context()
	logger := log.FromCtx(ctx)
	labels := metrics.RequestLabels{
		Result: metrics.ErrInternal,
	}
	segReq, ok := request.Message.(*path_mgmt.SegReq)
	if !ok {
		logger.Error("[segReqHandler] wrong message type, expected path_mgmt.SegReq",
			"msg", request.Message, "type", common.TypeOf(request.Message))
		metrics.Requests.Count(labels).Inc()
		return infra.MetricsErrInternal
	}
	logger.Debug("[segReqHandler] Received", "segReq", segReq)
	labels.DstISD = segReq.DstIA().I
	labels.CacheOnly = segReq.Flags.CacheOnly
	rw, ok := infra.ResponseWriterFromContext(ctx)
	if !ok {
		logger.Error("[segReqHandler] Response writer missing, unable to reply to client")
		metrics.Requests.Count(labels).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)

	segs, err := h.Fetcher.FetchSegs(ctx,
		segfetcher.Request{Src: segReq.SrcIA(), Dst: segReq.DstIA()})
	if err != nil {
		// TODO(lukedirtwalker): Define clearer the different errors that can
		// occur and depending on them reply / return different error codes.
		logger.Error("Failed to handle request", "err", err)
		sendAck(proto.Ack_ErrCode_reject, err.Error())
		metrics.Requests.Count(labels.WithResult(segfetcher.ErrToMetricsLabel(err))).Inc()
		return infra.MetricsErrInternal
	}
	labels.SegType = metrics.DetermineReplyType(segs)
	revs, err := revcache.RelevantRevInfos(ctx, h.RevCache, segs.Up, segs.Core, segs.Down)
	if err != nil {
		logger.Info("[segReqHandler] Failed to find relevant revocations for reply", "err", err)
		// the client might still be able to use the segments so continue here.
	}
	reply := &path_mgmt.SegReply{
		Req: segReq,
		Recs: &path_mgmt.SegRecs{
			Recs:      segsToRecs(ctx, segs),
			SRevInfos: revs,
		},
	}
	if err = rw.SendSegReply(ctx, reply); err != nil {
		logger.Error("[segReqHandler] Failed to send reply", "err", err)
		metrics.Requests.Count(labels.WithResult(metrics.ErrNetwork)).Inc()
		return infra.MetricsErrInternal
	}
	logger.Debug("[segReqHandler] Replied with segments", "segs", len(reply.Recs.Recs))
	labels = labels.WithResult(metrics.OkSuccess)
	metrics.Requests.Count(labels).Inc()
	metrics.Requests.RepliedSegs(labels.RequestOkLabels).Add(float64(len(reply.Recs.Recs)))
	metrics.Requests.RepliedRevs(labels.RequestOkLabels).Add(float64(len(reply.Recs.SRevInfos)))
	return infra.MetricsResultOk
}

// CreateLocalInfo creates the local info oracle.
func CreateLocalInfo(core bool, ia addr.IA, inspector trust.Inspector) segfetcher.LocalInfo {
	if core {
		return &CoreLocalInfo{
			CoreChecker: CoreChecker{Inspector: inspector},
			LocalIA:     ia,
		}
	}
	return &NonCoreLocalInfo{
		LocalIA: ia,
	}
}

func createPathDB(db pathdb.PathDB, localInfo segfetcher.LocalInfo) pathdb.PathDB {
	return &PathDB{
		PathDB:    db,
		LocalInfo: localInfo,
	}
}

// CreateNonCoreDstProvider creates a destination provider for a non-core AS.
func CreateNonCoreDstProvider(ia addr.IA, pather Pather, pathDB pathdb.PathDB,
	revCache revcache.RevCache, inspector trust.Inspector) segfetcher.DstProvider {

	return &nonCoreDstProvider{
		SegSelector: SegSelector{
			PathDB:   pathDB,
			RevCache: revCache,
		},
		inspector:   inspector,
		coreChecker: CoreChecker{Inspector: inspector},
		localIA:     ia,
		pathDB:      pathDB,
		pather:      pather,
	}
}

// CreateCoreDstProvider creates destination provider for a core AS.
func CreateCoreDstProvider(ia addr.IA, pather Pather, pathDB pathdb.PathDB,
	revCache revcache.RevCache) segfetcher.DstProvider {

	return &coreDstProvider{
		SegSelector: SegSelector{
			PathDB:   pathDB,
			RevCache: revCache,
		},
		localIA: ia,
		pathDB:  pathDB,
		pather:  pather,
	}
}
