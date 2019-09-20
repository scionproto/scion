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
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
)

// CryptoProvider provides crypto material. A crypto provider can spawn network
// request if necessary and permitted.
type CryptoProvider interface {
	// GetTRC asks the trust store to return a valid and active TRC for isd,
	// unless inactive TRCs are specifically allowed. The optionally configured
	// server is queried over the network if the TRC is not available locally.
	// Otherwise, the default server is queried.
	GetTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
		opts infra.TRCOpts) (*trc.TRC, error)
	// GetRawTRC behaves the same as GetTRC, except returning the raw signed TRC.
	GetRawTRC(ctx context.Context, isd addr.ISD, version scrypto.Version,
		opts infra.TRCOpts, client net.Addr) ([]byte, error)
	// GetRawChain asks the trust store to return a valid and active certificate
	// chain, unless inactive chains are specifically allowed. The optionally
	// configured server is queried over the network if the certificate chain is
	// not available locally. Otherwise, the default server is queried.
	GetRawChain(ctx context.Context, ia addr.IA, version scrypto.Version,
		opts infra.ChainOpts, client net.Addr) ([]byte, error)
}
