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

package trust

import "github.com/scionproto/scion/go/lib/infra"

var (
	// NewChainPushHandler allows instantiating the private chain push handler for black-box
	// testing.
	NewChainPushHandler = newTestChainPushHandler
	// NewTRCPushHandler allows instantiating the private TRC push handler for black-box
	// testing.
	NewTRCPushHandler = newTestTRCPushHandler
	// NewChainReqHandler allows instantiating the private certificate chain
	// request handler for black-box testing.
	NewChainReqHandler = newTestChainReqHandler
	// NewTRCReqHandler allows instantiating the private trc request handler for
	// black-box testing.
	NewTRCReqHandler = newTestTRCReqResolver
)

// newTestChainReqHandler returns a new resolver for testing.
func newTestChainReqHandler(request *infra.Request, provider CryptoProvider) *chainReqHandler {
	return &chainReqHandler{
		request:  request,
		provider: provider,
	}
}

// newTestResolver returns a new resolver for testing.
func newTestTRCReqResolver(request *infra.Request, provider CryptoProvider) *trcReqHandler {
	return &trcReqHandler{
		request:  request,
		provider: provider,
	}
}

// newChainPushHandler returns a new chain push handler for testing.
func newTestChainPushHandler(request *infra.Request, provider CryptoProvider,
	inserter Inserter) *chainPushHandler {

	return &chainPushHandler{
		request:  request,
		provider: provider,
		inserter: inserter,
	}
}

// newTRCPushHandler returns a new TRC push handler for testing.
func newTestTRCPushHandler(request *infra.Request, provider CryptoProvider,
	inserter Inserter) *trcPushHandler {

	return &trcPushHandler{
		request:  request,
		provider: provider,
		inserter: inserter,
	}
}
