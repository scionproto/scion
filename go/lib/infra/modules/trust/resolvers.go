// Copyright 2018 ETH Zurich, Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

// trcRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type trcRequest struct {
	isd       addr.ISD
	version   uint64
	cacheOnly bool
	id        uint64
	server    net.Addr
	// If postHook is set, run the callback to verify the downloaded object and insert into
	// the database. Also, used to generate different DedupeKeys for requests
	// for valid vs invalid crypto.
	postHook ValidateTRCFunc
}

// chainRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type chainRequest struct {
	ia        addr.IA
	version   uint64
	cacheOnly bool
	id        uint64
	server    net.Addr
	// If postHook is set, run the callback to verify the downloaded object and insert into
	// the database. Also, used to generate different DedupeKeys for requests
	// for valid vs invalid crypto.
	postHook ValidateChainFunc
}

type ValidateTRCFunc func(ctx context.Context, trcObj *trc.TRC) error

type ValidateChainFunc func(ctx context.Context, chain *cert.Chain) error
