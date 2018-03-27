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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/infra/dedupe"
)

var _ dedupe.Request = (*trcRequest)(nil)

// trcRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type trcRequest struct {
	isd       addr.ISD
	version   uint64
	cacheOnly bool
	id        uint64
	source    net.Addr
	// If postHook is set, run the callback to verify the downloaded object and insert into
	// the database. Also, used to generate different DedupeKeys for requests
	// for valid vs invalid crypto.
	postHook ValidateTRCF
}

func (req *trcRequest) DedupeKey() string {
	// Include the existence of a validation hook in the dedupe key. This
	// allows callers to request both verified and unverified crypto at the
	// same (thus avoiding the case where unverified requests block verified
	// requests from running).
	return fmt.Sprintf("%dv%d %t %s", req.isd, req.version, req.postHook != nil, req.source)
}

func (req *trcRequest) BroadcastKey() string {
	return fmt.Sprintf("%dv%d", req.isd, req.version)
}

var _ dedupe.Request = (*chainRequest)(nil)

// chainRequest objects describe a single request and are passed from the trust
// store to the background resolvers.
type chainRequest struct {
	ia        addr.IA
	version   uint64
	cacheOnly bool
	id        uint64
	source    net.Addr
	// If postHook is set, run the callback to verify the downloaded object and insert into
	// the database. Also, used to generate different DedupeKeys for requests
	// for valid vs invalid crypto.
	postHook ValidateChainF
}

func (req *chainRequest) DedupeKey() string {
	// Include the existence of a validation hook in the dedupe key. This
	// allows callers to request both verified and unverified crypto at the
	// same (thus avoiding the case where unverified requests block verified
	// requests from running).
	return fmt.Sprintf("%sv%d %t %s", req.ia, req.version, req.postHook != nil, req.source)
}

func (req *chainRequest) BroadcastKey() string {
	return fmt.Sprintf("%sv%d", req.ia, req.version)
}

type ValidateTRCF func(ctx context.Context, trcObj *trc.TRC) error

type ValidateChainF func(ctx context.Context, chain *cert.Chain) error
