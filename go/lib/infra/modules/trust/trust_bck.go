// Copyright 2018 ETH Zurich
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

package trust

import (
	"context"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	liblog "github.com/scionproto/scion/go/lib/log"
)

const (
	// Minimum time between sending network packets for the same object.
	MinimumDelta = 30 * time.Second
)

type trcResolver struct {
	msger    infra.Messenger
	lastSent map[trcRequest]time.Time
	trustdb  *trustdb.DB
	requests <-chan trcRequest
	events   *eventMap
	log      log.Logger
}

func (resolver *trcResolver) Run() {
	defer liblog.LogPanicAndExit()
	resolver.lastSent = make(map[trcRequest]time.Time)
	for request := range resolver.requests {
		lastSent := resolver.lastSent[request]
		now := time.Now()
		if now.Sub(lastSent) > MinimumDelta {
			// We sent out the last request a long time ago and it expired by now.
			// Send one again.
			resolver.lastSent[request] = now
			handler := &trcResolverHandler{
				resolver: resolver,
				request:  request,
				log: resolver.log.New("id", logext.RandId(4),
					"goroutine", "trcResolverHandler.Handle", "request", request),
			}
			go handler.Handle()
		} else {
			// A request is already pending, ignore new ones
		}
	}
}

type trcResolverHandler struct {
	resolver *trcResolver
	request  trcRequest
	log      log.Logger
}

func (handler *trcResolverHandler) Handle() {
	defer liblog.LogPanicAndExit()
	ctx, cancelF := context.WithTimeout(context.Background(), MinimumDelta)
	defer cancelF()
	handler.log.Info("Start TRC resolver handler", "request", handler.request)

	// Check ahead of time if we have a verifier TRC
	if handler.request.verifier == nil {
		handler.log.Warn("Unable to fetch TRC without a trusted TRC")
		return
	}
	trcReqMsg := &cert_mgmt.TRCReq{
		ISD:       handler.request.isd,
		Version:   handler.request.version,
		CacheOnly: false,
	}
	// FIXME(scrye): Add SVC support for write ops in snet
	csAddress := net.Addr(nil)
	trcMessage, err := handler.resolver.msger.GetTRC(ctx, trcReqMsg, csAddress)
	if err != nil {
		handler.log.Warn("Unable to get TRC from peer", "err", common.FmtError(err))
		return
	}
	trcObj, err := trcMessage.TRC()
	if err != nil {
		handler.log.Warn("Unable to parse TRC message", "err", common.FmtError(err), "msg", trcMessage)
		return
	}

	// Verify trc based on the verifier in the request
	// XXX(scrye): full verification is not implemented (e.g., no cross signature support)
	if _, err = trcObj.Verify(handler.request.verifier); err != nil {
		handler.log.Warn("TRC verification error", "err", common.FmtError(err))
		return
	}

	err = handler.resolver.trustdb.InsertTRCCtx(ctx, handler.request.isd, handler.request.version, trcObj)
	if err != nil {
		handler.log.Warn("Unable to store trc in database", "err", err)
	}
	handler.resolver.events.Signal(handler.request.Key())
}

type chainResolver struct {
	msger    infra.Messenger
	lastSent map[chainRequest]time.Time
	trustdb  *trustdb.DB
	requests <-chan chainRequest
	events   *eventMap
	log      log.Logger
}

func (resolver *chainResolver) Run() {
	defer liblog.LogPanicAndExit()
	resolver.lastSent = make(map[chainRequest]time.Time)
	for request := range resolver.requests {
		lastSent := resolver.lastSent[request]
		now := time.Now()
		if now.Sub(lastSent) > MinimumDelta {
			// We sent out the last request a long time ago and it expired by now.
			// Send one again.
			resolver.lastSent[request] = now
			handler := &chainResolverHandler{
				resolver: resolver,
				request:  request,
				log: resolver.log.New("id", logext.RandId(4),
					"goroutine", "chainResolverHandler.Handle", "request", request),
			}
			go handler.Handle()
		} else {
			// A request is already pending, ignore new ones
		}
	}
}

type chainResolverHandler struct {
	resolver *chainResolver
	request  chainRequest
	log      log.Logger
}

func (handler *chainResolverHandler) Handle() {
	defer liblog.LogPanicAndExit()
	ctx, cancelF := context.WithTimeout(context.Background(), MinimumDelta)
	defer cancelF()
	handler.log.Info("Start Chain resolver handler", "request", handler.request)

	// Check ahead of time if we have a verifier TRC
	if handler.request.verifier == nil {
		handler.log.Warn("Unable to fetch Chain without a trusted TRC")
		return
	}
	chainReqMsg := &cert_mgmt.ChainReq{
		RawIA:     handler.request.ia.IAInt(),
		Version:   handler.request.version,
		CacheOnly: false,
	}
	// FIXME(scrye): Add SVC support for write ops in snet
	csAddress := net.Addr(nil)
	chainMessage, err := handler.resolver.msger.GetCertChain(ctx, chainReqMsg, csAddress)
	if err != nil {
		handler.log.Warn("Unable to get CertChain from peer", "err", err)
		return
	}
	chain, err := chainMessage.Chain()
	if err != nil {
		handler.log.Warn("Unable to parse CertChain message", "err", err)
		return
	}

	// Verify chain based on the verifier in the request
	if err := chain.Verify(&handler.request.ia, handler.request.verifier); err != nil {
		handler.log.Warn("Chain verification failed", "err", common.FmtError(err))
		return
	}

	err = handler.resolver.trustdb.InsertChainCtx(ctx, handler.request.ia, handler.request.version, chain)
	if err != nil {
		handler.log.Warn("Unable to store CertChain in database", "err", err)
	}
	handler.resolver.events.Signal(handler.request.Key())
}
