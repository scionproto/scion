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

type requestI interface {
	// requestKey returns a string that is defined by the AS, Certificate
	// version and contacted address. Requests with the same requestKey are
	// throttled (i.e., at most one every MinimumDelta time).
	requestKey() string
	// responseKey returns a string that is completely defined by the AS and
	// Certificate version of the request. This can be used to create maps of
	// channels where any goroutine that is handling a request for an AS and
	// version can unblock the waiters on the channel, irrespective of contacted
	// address.
	responseKey() string
	// resolve builds a network message from the request, sends it on msger,
	// waits for the response, verifies it and finally inserts it into the
	// database.
	resolve(ctx context.Context, msger infra.Messenger, db *trustdb.DB) error
	// getErrorChan returns the channel the goroutine that submitted the
	// request is waiting on.
	getErrorChan() chan<- error
}

// resolver services requests from channel requests. Requests are throttled
// based on key, meaning that multiple requests arriving for the same key in
// the same MinimumDelta time slot will cause a single handler to spawn.
// The maximum lifetime of the handler is MinimumDelta + GracePeriod. Requests
// include error channels which are used by the resolver to communicate if the
// handler associated with a request encountered an error, and to unblock the
// submitter of the request.
type resolver struct {
	msger   infra.Messenger
	trustdb *trustdb.DB
	// channel from which the resolver receives requests from the frontend
	requests <-chan requestI
	// for each key maintain a completion channel that includes a sequence of
	// error channels. When the resolver receives a request, it writes the
	// error channel (on which the submitter of the request is waiting) to the
	// completionChannel for that key. When the handler completes (either
	// successfully or with an error), it writes the error result on each error
	// channel and then shuts itself down.
	completionChans map[string]chan chan<- error
	log             log.Logger
}

func (r *resolver) Run() {
	defer liblog.LogPanicAndExit()
	lastSent := make(map[string]time.Time)
	for request := range r.requests {
		// requestKey uniquely describes a (object, version, address) tuple,
		// while responseKey describes a (object, version) one. The resolver
		// throttles based on the requestKey, s.t. at most a single goroutine
		// every MinimumDelta is trying to reach an address. However, channels
		// containing the error channels requesters are waiting on are indexed
		// by responseKeys. Once any goroutine for any address has the desired
		// object, all waiters are unblocked irrespective of the address they
		// contacted. However, on error conditions, the signaling is done via
		// requestKey indexing (because the error might be related to a single
		// address).
		requestKey := request.requestKey()
		responseKey := request.responseKey()
		if now := time.Now(); now.Sub(lastSent[requestKey]) > MinimumDelta {
			// We sent out the last request to the address described in
			// requestKey a long time ago and it expired by now.  Send one
			// again.
			lastSent[requestKey] = now
			// FIXME(scrye): these references will leak channels unless
			// periodically cleaned from the maps.
			if r.completionChans[responseKey] == nil {
				r.completionChans[responseKey] = make(chan chan<- error, CompletionChanCap)
			}
			if r.completionChans[requestKey] == nil {
				r.completionChans[requestKey] = make(chan chan<- error, CompletionChanCap)
			}
			handler := &resolverHandler{
				resolver:              r,
				request:               request,
				successCompletionChan: r.completionChans[responseKey],
				failCompletionChan:    r.completionChans[requestKey],
				log: r.log.New("id", logext.RandId(4),
					"goroutine", "trcResolverHandler.Handle", "request", request),
			}
			go handler.Handle()
		}

		// A goroutine is already handling a request described by the same
		// requestKey. We need to register the error channel the requester is
		// waiting one with all the goroutines that are currently attempting to
		// grab the desired object from any address.
		select {
		case r.completionChans[responseKey] <- request.getErrorChan():
			// Do nothing
		default:
			request.getErrorChan() <- common.NewBasicError("Insufficient space in completion channel",
				nil, "request_key", requestKey)
			close(request.getErrorChan())
		}
	}
}

// resolverHandler is tasked with servicing a single request.
type resolverHandler struct {
	resolver *resolver
	request  requestI
	// when the handler exits successfully, read all the error channels from
	// successCompletionChan, write nil to each of them and finally close them.
	// This unblocks all goroutines waiting for (object, version)
	successCompletionChan chan chan<- error
	// when the handler exits with a failure, read all the error channels from
	// failCompleTionChan, write the error to each of them and finally close them.
	// This unblocks all goroutines waiting for (object, version, address)
	failCompletionChan chan chan<- error
	log                log.Logger
}

func (h *resolverHandler) Handle() {
	defer liblog.LogPanicAndExit()
	ctx, cancelF := context.WithTimeout(context.Background(), MinimumDelta+GracePeriod)
	defer cancelF()
	h.log.Info("Start resolver handler", "request", h.request)

	err := h.request.resolve(ctx, h.resolver.msger, h.resolver.trustdb)
	// Depending on error, choose whether to announce success or errors
	var announceChan chan chan<- error
	if err != nil {
		announceChan = h.failCompletionChan
	} else {
		announceChan = h.successCompletionChan
	}
	for {
		select {
		case errChan := <-announceChan:
			// Unblock the goroutine waiting for a message on errChan
			errChan <- err
			close(errChan)
		default:
			// Nobody is waiting for the result any more
			return
		}
	}
}

var _ requestI = trcRequest{}

// trcRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type trcRequest struct {
	isd      uint16
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
	errChan  chan error
}

func (req trcRequest) requestKey() string {
	return fmt.Sprintf("%dv%d %s", req.isd, req.version, req.hint.String())
}

func (req trcRequest) responseKey() string {
	return fmt.Sprintf("%dv%d", req.isd, req.version)
}

func (req trcRequest) resolve(ctx context.Context, msger infra.Messenger, db *trustdb.DB) error {
	// Check ahead of time if we have a verifier TRC
	if req.verifier == nil {
		return common.NewBasicError("Unable to fetch TRC without a trusted TRC", nil)
	}
	// FIXME(scrye): Implement CacheOnly support.
	trcReqMsg := &cert_mgmt.TRCReq{
		ISD:       req.isd,
		Version:   req.version,
		CacheOnly: true,
	}
	var address net.Addr
	if req.hint != nil {
		address = req.hint
	} else {
		// FIXME(scrye): Add SVC support for write ops in snet
		address = net.Addr(nil)
	}
	trcMessage, err := msger.GetTRC(ctx, trcReqMsg, address)
	if err != nil {
		return err
	}
	trcObj, err := trcMessage.TRC()
	if err != nil {
		return common.NewBasicError("Unable to parse TRC message", err, "msg", trcMessage)
	}

	// Verify trc based on the verifier in the request
	// XXX(scrye): full verification is not implemented (e.g., no cross signature support)
	if _, err = trcObj.Verify(req.verifier); err != nil {
		return common.NewBasicError("TRC verification error", err)
	}
	if err := db.InsertTRCCtx(ctx, req.isd, req.version, trcObj); err != nil {
		return common.NewBasicError("Unable to store TRC in database", err)
	}
	return nil
}

func (req trcRequest) getErrorChan() chan<- error {
	return req.errChan
}

var _ requestI = chainRequest{}

// chainRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type chainRequest struct {
	ia       addr.ISD_AS
	version  uint64
	hint     net.Addr
	verifier *trc.TRC
	errChan  chan error
}

func (req chainRequest) requestKey() string {
	return fmt.Sprintf("%sv%d %s", req.ia, req.version, req.hint.String())
}

func (req chainRequest) responseKey() string {
	return fmt.Sprintf("%sv%d", req.ia, req.version)
}

func (req chainRequest) resolve(ctx context.Context, msger infra.Messenger, db *trustdb.DB) error {
	// Check ahead of time if we have a verifier TRC
	if req.verifier == nil {
		return common.NewBasicError("Unable to fetch Chain without a trusted TRC", nil)
	}
	// FIXME(scrye): Implement CacheOnly support.
	chainReqMsg := &cert_mgmt.ChainReq{
		RawIA:     req.ia.IAInt(),
		Version:   req.version,
		CacheOnly: true,
	}
	var address net.Addr
	if req.hint != nil {
		address = req.hint
	} else {
		// FIXME(scrye): Add SVC support for write ops in snet
		address = net.Addr(nil)
	}
	chainMessage, err := msger.GetCertChain(ctx, chainReqMsg, address)
	if err != nil {
		return common.NewBasicError("Unable to get CertChain from peer", err)
	}
	chain, err := chainMessage.Chain()
	if err != nil {
		return common.NewBasicError("Unable to parse CertChain message", err)
	}

	// Verify chain based on the verifier in the request
	if err := chain.Verify(&req.ia, req.verifier); err != nil {
		return common.NewBasicError("Chain verification failed", err)
	}
	err = db.InsertChainCtx(ctx, req.ia, req.version, chain)
	if err != nil {
		return common.NewBasicError("Unable to store CertChain in database", err)
	}
	return nil
}

func (req chainRequest) getErrorChan() chan<- error {
	return req.errChan
}
