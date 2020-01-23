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
	"time"

	"github.com/scionproto/scion/go/cs/handlers"
	"github.com/scionproto/scion/go/cs/metrics"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pathdb"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/proto"
)

type handler struct {
	fetcher  *segfetcher.Fetcher
	revCache revcache.RevCache
}

func NewHandler(args handlers.HandlerArgs) infra.Handler {
	core := args.TopoProvider.Get().Core()
	localInfo := CreateLocalInfo(args, core)
	args.PathDB = createPathDB(args.PathDB, localInfo)
	return &handler{
		fetcher: segfetcher.FetcherConfig{
			QueryInterval:       args.QueryInterval,
			LocalIA:             args.IA,
			VerificationFactory: args.VerifierFactory,
			PathDB:              args.PathDB,
			RevCache:            args.RevCache,
			RequestAPI:          args.SegRequestAPI,
			DstProvider:         CreateDstProvider(args, core),
			Splitter:            &Splitter{ASInspector: args.ASInspector},
			MetricsNamespace:    metrics.PSNamespace,
			LocalInfo:           localInfo,
		}.New(),
		revCache: args.RevCache,
	}
}

func (h *handler) Handle(request *infra.Request) *infra.HandlerResult {
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
		logger.Warn("[segReqHandler] Unable to reply to client, no response writer found")
		metrics.Requests.Count(labels).Inc()
		return infra.MetricsErrInternal
	}
	sendAck := messenger.SendAckHelper(ctx, rw)

	segs, err := h.fetcher.FetchSegs(ctx,
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
	revs, err := revcache.RelevantRevInfos(ctx, h.revCache, segs.Up, segs.Core, segs.Down)
	if err != nil {
		logger.Warn("[segReqHandler] Failed to find relevant revocations for reply", "err", err)
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

func createValidator(args handlers.HandlerArgs, core bool) segfetcher.Validator {
	base := BaseValidator{
		CoreChecker: CoreChecker{Inspector: args.ASInspector},
	}
	if !core {
		return &base
	}
	return &CoreValidator{BaseValidator: base}
}

// CreateLocalInfo creates the local info oracle.
func CreateLocalInfo(args handlers.HandlerArgs, core bool) LocalInfo {
	if core {
		return &CoreLocalInfo{
			CoreChecker: CoreChecker{Inspector: args.ASInspector},
			LocalIA:     args.IA,
		}
	}
	return &NonCoreLocalInfo{
		LocalIA: args.IA,
	}
}

func createPathDB(db pathdb.PathDB, localInfo LocalInfo) pathdb.PathDB {
	return &PathDB{
		PathDB:     db,
		LocalInfo:  localInfo,
		RetrySleep: 500 * time.Millisecond,
	}
}

// CreateDstProvider creates the destination provider.
func CreateDstProvider(args handlers.HandlerArgs, core bool) segfetcher.DstProvider {
	selector := SegSelector{
		PathDB:   args.PathDB,
		RevCache: args.RevCache,
	}
	if core {
		return &coreDstProvider{
			SegSelector:  selector,
			localIA:      args.IA,
			pathDB:       args.PathDB,
			topoProvider: args.TopoProvider,
		}
	}
	return &nonCoreDstProvider{
		SegSelector:  selector,
		inspector:    args.ASInspector,
		coreChecker:  CoreChecker{Inspector: args.ASInspector},
		localIA:      args.IA,
		pathDB:       args.PathDB,
		topoProvider: args.TopoProvider,
	}
}
