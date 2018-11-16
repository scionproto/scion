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

package trustdb

import (
	"context"
	"io"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

// TrustDB is the interface that all trust databases have to implement.
type TrustDB interface {
	// GetIssCertVersion returns the specified version of the issuer certificate for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetIssCertMaxVersion.
	GetIssCertVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Certificate, error)
	// GetIssCertMaxVersion returns the max version of the issuer certificate for ia.
	GetIssCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error)
	// InsertIssCert inserts the issuer certificate.
	InsertIssCert(ctx context.Context, crt *cert.Certificate) (int64, error)
	// GetLeafCertVersion returns the specified version of the leaf certificate for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetLeafCertMaxVersion.
	GetLeafCertVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Certificate, error)
	// GetLeafCertMaxVersion returns the max version of the leaf certificate for ia.
	GetLeafCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error)
	// InsertLeafCert inserts the leaf certificate.
	InsertLeafCert(ctx context.Context, crt *cert.Certificate) (int64, error)
	// GetChainVersion returns the specified version of the certificate chain for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetChainMaxVersion.
	GetChainVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error)
	// GetChainMaxVersion returns the max version of the chain for ia.
	GetChainMaxVersion(ctx context.Context, ia addr.IA) (*cert.Chain, error)
	// GetAllChains returns all chains in the database.
	GetAllChains(ctx context.Context) ([]*cert.Chain, error)
	// InsertChain inserts chain into the database. The first return value is the
	// number of rows affected.
	InsertChain(ctx context.Context, chain *cert.Chain) (int64, error)
	// GetTRCVersion returns the specified version of the TRC for
	// isd. If version is scrypto.LatestVer, this is equivalent to GetTRCMaxVersion.
	GetTRCVersion(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error)
	// GetTRCMaxVersion returns the max version of the TRC for ia.
	GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error)
	// InsertTRC inserts trcobj into the database. The first return value is the
	// number of rows affected.
	InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error)
	// GetAllTRCs fetches all TRCs from the database.
	GetAllTRCs(ctx context.Context) ([]*trc.TRC, error)
	io.Closer
}
