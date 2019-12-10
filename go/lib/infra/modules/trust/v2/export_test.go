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

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	// NewCryptoProvider allows instantiating the private cryptoProvider for
	// black-box testing.
	NewCryptoProvider = newTestCryptoProvider
	// NewCSRouter allows instantiating the private CS router for black-box
	// testing.
	NewCSRouter = newTestCSRouter
	// NewFwdInserter allows instantiating the private forwarding
	// inserter for black-box testing.
	NewFwdInserter = newTestFwdInserter
	// NewInserter allows instantiating the private inserter for black-box
	// testing.
	NewInserter = newTestInserter
	// NewTestInspector allows instantiating the private inspector for black-box
	// testing.
	NewTestInspector = newTestInspector
	// NewLocalRouter allows instantiating the private resolver for black-box
	// testing.
	NewLocalRouter = newTestLocalRouter
	// NewResolver allows instantiating the private resolver for black-box
	// testing.
	NewResolver = newTestResolver
	// NewChainPushHandler allows instantiating the private chain push handler for black-box
	// testing.
	NewChainPushHandler = newTestChainPushHandler
	// NewTRCPushHandler allows instantiating the private TRC push handler for black-box
	// testing.
	NewTRCPushHandler = newTestTRCPushHandler
)

// newTestCryptoProvider returns a new crypto provider for testing.
func newTestCryptoProvider(db DBRead, recurser Recurser, resolver Resolver, router Router,
	alwaysCacheOnly bool) CryptoProvider {

	return &cryptoProvider{
		db:              db,
		recurser:        recurser,
		resolver:        resolver,
		router:          router,
		alwaysCacheOnly: alwaysCacheOnly,
	}
}

// newTestCSRouter returns a new router for testing.
func newTestCSRouter(isd addr.ISD, router snet.Router, db TRCRead) Router {
	return &csRouter{
		isd:    isd,
		router: router,
		db:     db,
	}
}

// newTestFwdInserter returns a new forwarding inserter for testing.
func newTestFwdInserter(db ReadWrite, rpc RPC) Inserter {
	return &fwdInserter{
		baseInserter: baseInserter{
			db: db,
		},
		rpc: rpc,
	}
}

// newTestInserter returns a new inserter for testing.
func newTestInserter(db ReadWrite, unsafe bool) Inserter {
	return &inserter{
		baseInserter: baseInserter{
			db:     db,
			unsafe: unsafe,
		},
	}
}

// newTestInspector returns a new inspector for testing.
func newTestInspector(provider CryptoProvider) Inspector {
	return &inspector{
		provider: provider,
	}
}

// newTestLocalRouter returns a new router for testing.
func newTestLocalRouter(ia addr.IA) Router {
	return &localRouter{ia: ia}
}

// newTestResolver returns a new resolver for testing.
func newTestResolver(db DBRead, inserter Inserter, rpc RPC) Resolver {
	return &resolver{
		db:       db,
		inserter: inserter,
		rpc:      rpc,
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
