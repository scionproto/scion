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
	"fmt"
	"net"
	"time"

	log "github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	liblog "github.com/scionproto/scion/go/lib/log"
)

const (
	// Minimum time between sending network packets for the same object.
	MinimumDelta = 2 * time.Second
	// Time in addition to MinimumDelta in which a handler attempts to handle the request
	GracePeriod = 2 * time.Second
	// Maximum number of waiters in a completion channel
	CompletionChanCap = 1 << 8
)

// trcResolver services requests from channel requests. Requests are throttled
// based on key, meaning that multiple requests arriving for the same key in
// the same MinimumDelta time slot will cause a single handler to spawn.
// The maximum lifetime of the handler is MinimumDelta + GracePeriod. Requests
// include error channels which are used by the resolver to communicate if the
// handler associated with a request encountered an error, and to unblock the
// submitter of the request.
type trcResolver struct {
	msger   infra.Messenger
	trustdb *trustdb.DB
	// channel from which the resolver receives requests from the frontend
	requests <-chan trcRequest
	// for each key maintain a completion channel that includes a sequence of
	// error channels. When the resolver receives a request, it writes the
	// error channel (on which the submitter of the request is waiting) to the
	// completionChannel for that key. When the handler completes (either
	// successfully or with an error), it writes the error result on each error
	// channel and then shuts itself down.
	completionChans map[string]chan chan error
	log             log.Logger
}

func (resolver *trcResolver) Run() {
	defer liblog.LogPanicAndExit()
	lastSent := make(map[string]time.Time)
	for request := range resolver.requests {
		key := request.Key()
		if now := time.Now(); now.Sub(lastSent[key]) > MinimumDelta {
			// We sent out the last request a long time ago and it expired by now.
			// Send one again.
			lastSent[key] = now
			if resolver.completionChans[key] != nil {
				close(resolver.completionChans[key])
			}
			resolver.completionChans[key] = make(chan chan error, CompletionChanCap)
			handler := &trcResolverHandler{
				resolver:       resolver,
				request:        request,
				completionChan: resolver.completionChans[key],
				log: resolver.log.New("id", logext.RandId(4),
					"goroutine", "trcResolverHandler.Handle", "request", request),
			}
			go handler.Handle()
		}

		select {
		case resolver.completionChans[key] <- request.errChan:
			// Do nothing
		default:
			request.errChan <- common.NewBasicError("Insufficient space in completion channel",
				nil, "request_key", key)
			close(request.errChan)
		}
	}
}

type trcResolverHandler struct {
	resolver *trcResolver
	request  trcRequest
	// when the handler exits, read all the error channels from completionChan,
	// write the result of the handler to each of them and finally close them.
	completionChan chan chan error
	log            log.Logger
}

func (handler *trcResolverHandler) Handle() {
	var err error
	defer liblog.LogPanicAndExit()
	ctx, cancelF := context.WithTimeout(context.Background(), MinimumDelta+GracePeriod)
	defer cancelF()
	handler.log.Info("Start TRC resolver handler", "request", handler.request)

	defer func() {
		// Once MinimumDelta expires, if the resolver receives a new request
		// for the same request.Key() that this handler services, it closes errChan
		// and all the resources associated with it get cleaned up. If
		// the resolver doesn't receive a request, ctx.Done() returns after
		// MinimumDelta+GracePeriod at the latest.
		for {
			select {
			case errChan := <-handler.completionChan:
				errChan <- err
				close(errChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Check ahead of time if we have a verifier TRC
	if handler.request.verifier == nil {
		err = common.NewBasicError("Unable to fetch TRC without a trusted TRC", nil)
		return
	}
	trcReqMsg := &cert_mgmt.TRCReq{
		ISD:       handler.request.isd,
		Version:   handler.request.version,
		CacheOnly: false,
	}
	var csAddress net.Addr
	if handler.request.hint != nil {
		csAddress = handler.request.hint
	} else {
		// FIXME(scrye): Add SVC support for write ops in snet
		csAddress = net.Addr(nil)
	}
	trcMessage, err := handler.resolver.msger.GetTRC(ctx, trcReqMsg, csAddress)
	if err != nil {
		return
	}
	trcObj, err := trcMessage.TRC()
	if err != nil {
		err = common.NewBasicError("Unable to parse TRC message", err, "msg", trcMessage)
		return
	}

	// Verify trc based on the verifier in the request
	// XXX(scrye): full verification is not implemented (e.g., no cross signature support)
	if _, err = trcObj.Verify(handler.request.verifier); err != nil {
		err = common.NewBasicError("TRC verification error", err)
		return
	}

	err = handler.resolver.trustdb.InsertTRCCtx(ctx, handler.request.isd, handler.request.version,
		trcObj)
	if err != nil {
		err = common.NewBasicError("Unable to store TRC in database", err)
		return
	}
}

// trcRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type trcRequest struct {
	isd      uint16
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
	errChan  chan error
}

// Key returns a string that describes the request. Requests with the same key
// are throttled (i.e., at most one every MinimumDelta time).
func (req trcRequest) Key() string {
	return fmt.Sprintf("%d-%d-%s", req.isd, req.version, req.hint.String())
}

// chainResolver services requests from channel requests. Requests are throttled
// based on key, meaning that multiple requests arriving for the same key in
// the same MinimumDelta time slot will cause a single handler to spawn.
// The maximum lifetime of the handler is MinimumDelta + GracePeriod. Requests
// include error channels which are used by the resolver to communicate if the
// handler associated with a request encountered an error, and to unblock the
// submitter of the request.
type chainResolver struct {
	msger   infra.Messenger
	trustdb *trustdb.DB
	// channel from which the resolver receives requests from the frontend
	requests <-chan chainRequest
	// for each key maintain a completion channel that includes a sequence of
	// error channels. When the resolver receives a request, it writes the
	// error channel (on which the submitter of the request is waiting) to the
	// completionChannel for that key. When the handler completes (either
	// successfully or with an error), it writes the error result on each error
	// channel and then shuts itself down.
	completionChans map[string]chan chan error
	log             log.Logger
}

func (resolver *chainResolver) Run() {
	defer liblog.LogPanicAndExit()
	lastSent := make(map[string]time.Time)
	for request := range resolver.requests {
		key := request.Key()
		if now := time.Now(); now.Sub(lastSent[key]) > MinimumDelta {
			// We sent out the last request a long time ago and it expired by now.
			// Send one again.
			lastSent[key] = now
			if resolver.completionChans[key] != nil {
				close(resolver.completionChans[key])
			}
			resolver.completionChans[key] = make(chan chan error, CompletionChanCap)
			handler := &chainResolverHandler{
				resolver:       resolver,
				request:        request,
				completionChan: resolver.completionChans[key],
				log: resolver.log.New("id", logext.RandId(4),
					"goroutine", "chainResolverHandler.Handle", "request", request),
			}
			go handler.Handle()
		}

		select {
		case resolver.completionChans[key] <- request.errChan:
			// Do nothing
		default:
			request.errChan <- common.NewBasicError("Insufficient space in completion channel",
				nil, "request_key", key)
			close(request.errChan)
		}
	}
}

type chainResolverHandler struct {
	resolver *chainResolver
	request  chainRequest
	// when the handler exits, read all the error channels from completionChan,
	// write the result of the handler to each of them and finally close them.
	completionChan chan chan error
	log            log.Logger
}

func (handler *chainResolverHandler) Handle() {
	var err error
	defer liblog.LogPanicAndExit()
	ctx, cancelF := context.WithTimeout(context.Background(), MinimumDelta+GracePeriod)
	defer cancelF()
	handler.log.Info("Start Chain resolver handler", "request", handler.request)

	defer func() {
		// Once MinimumDelta expires, if the resolver receives a new request
		// for the same request.Key() that this handler services, it closes errChan
		// and all the resources associated with it get cleaned up. If
		// the resolver doesn't receive a request, ctx.Done() returns after
		// MinimumDelta+GracePeriod at the latest.
		for {
			select {
			case errChan := <-handler.completionChan:
				errChan <- err
				close(errChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Check ahead of time if we have a verifier TRC
	if handler.request.verifier == nil {
		err = common.NewBasicError("Unable to fetch Chain without a trusted TRC", nil)
		return
	}
	chainReqMsg := &cert_mgmt.ChainReq{
		RawIA:     handler.request.ia.IAInt(),
		Version:   handler.request.version,
		CacheOnly: false,
	}
	var csAddress net.Addr
	if handler.request.hint != nil {
		csAddress = handler.request.hint
	} else {
		// FIXME(scrye): Add SVC support for write ops in snet
		csAddress = net.Addr(nil)
	}
	chainMessage, err := handler.resolver.msger.GetCertChain(ctx, chainReqMsg, csAddress)
	if err != nil {
		err = common.NewBasicError("Unable to get CertChain from peer", err)
		return
	}
	chain, err := chainMessage.Chain()
	if err != nil {
		err = common.NewBasicError("Unable to parse CertChain message", err)
		return
	}

	// Verify chain based on the verifier in the request
	err = chain.Verify(&handler.request.ia, handler.request.verifier)
	if err != nil {
		err = common.NewBasicError("Chain verification failed", err)
		return
	}

	err = handler.resolver.trustdb.InsertChainCtx(ctx, handler.request.ia, handler.request.version,
		chain)
	if err != nil {
		err = common.NewBasicError("Unable to store CertChain in database", err)
		return
	}
}

// chainRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type chainRequest struct {
	ia       addr.ISD_AS
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
	errChan  chan error
}

// Key returns a string that describes the request. Requests with the same key
// are throttled (i.e., at most one every MinimumDelta time).
func (req chainRequest) Key() string {
	return fmt.Sprintf("%d-%d-%s", req.ia, req.version, req.hint.String())
}
