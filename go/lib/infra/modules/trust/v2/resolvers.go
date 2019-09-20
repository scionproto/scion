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
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
)

// Resolver resolves verified trust material.
type Resolver interface {
	// TRC resolves the decoded signed TRC. Missing links in the TRC
	// verification chain are also requested.
	TRC(ctx context.Context, req TRCReq, server net.Addr) (DecodedTRC, error)
	// Chain resolves the raw signed certificate chain. If the issuing TRC is
	// missing, it is also requested.
	Chain(ctx context.Context, req ChainReq, server net.Addr) (DecodedChain, error)
}

// TRCReq holds the values of a TRC request.
type TRCReq struct {
	ISD       addr.ISD
	Version   scrypto.Version
	CacheOnly bool
}

// ChainReq holds the values of a certificate chain request.
type ChainReq struct {
	IA        addr.IA
	Version   scrypto.Version
	CacheOnly bool
}
