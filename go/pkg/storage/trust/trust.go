// Copyright 2021 Anapaya Systems
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
	"crypto/sha256"
	"crypto/x509"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
)

// TRCsQuery identifies a set of TRCs that need to be looked up.
type TRCsQuery struct {
	// ISD is the ISD identifier of the TRCs.
	ISD []addr.ISD
	// Latest indicates if only the latest TRC of each ISD is requested.
	Latest bool
}

type TrustAPI interface {
	// SignedTRCs returns the TRCs matching the TRCsQuery from the trust database.
	SignedTRCs(context.Context, TRCsQuery) (cppki.SignedTRCs, error)
	// Chain looks up the chain for a given ChainID.
	Chain(context.Context, []byte) ([]*x509.Certificate, error)
}

// ChainID maps certificate chain to an ID
func ChainID(chain []*x509.Certificate) []byte {
	h := sha256.New()
	h.Write(chain[0].Raw)
	h.Write(chain[1].Raw)
	return h.Sum(nil)
}
