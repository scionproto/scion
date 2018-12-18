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

// Package trustdb provides wrappers for SQL calls for managing a database
// containing TRCs and Certificate Chains.
package trustdb

import (
	"context"
	"database/sql"
	"io"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

// TrustDB is a database containing Certificates, Chains and TRCs, stored in JSON format.
// TrustDB is the interface that all trust databases have to implement.
// Read and Write interactions with this interface have to happen in individual transactions
// (either explicit or implicit).
type TrustDB interface {
	Read
	Write
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	io.Closer
}

// Read contains all read operation of the trust DB.
// On errors, GetXxx methods return nil and the error. If no error occurred,
// but the database query yielded 0 results, the first returned value is nil.
type Read interface {
	// GetIssCertVersion returns the specified version of the issuer certificate for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetIssCertMaxVersion.
	GetIssCertVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Certificate, error)
	// GetIssCertMaxVersion returns the max version of the issuer certificate for ia.
	GetIssCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error)
	// GetLeafCertVersion returns the specified version of the leaf certificate for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetLeafCertMaxVersion.
	GetLeafCertVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Certificate, error)
	// GetLeafCertMaxVersion returns the max version of the leaf certificate for ia.
	GetLeafCertMaxVersion(ctx context.Context, ia addr.IA) (*cert.Certificate, error)
	// GetChainVersion returns the specified version of the certificate chain for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetChainMaxVersion.
	GetChainVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error)
	// GetChainMaxVersion returns the max version of the chain for ia.
	GetChainMaxVersion(ctx context.Context, ia addr.IA) (*cert.Chain, error)
	// GetAllChains returns all chains in the database.
	GetAllChains(ctx context.Context) ([]*cert.Chain, error)
	// GetTRCVersion returns the specified version of the TRC for
	// isd. If version is scrypto.LatestVer, this is equivalent to GetTRCMaxVersion.
	GetTRCVersion(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error)
	// GetTRCMaxVersion returns the max version of the TRC for ia.
	GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error)
	// GetAllTRCs fetches all TRCs from the database.
	GetAllTRCs(ctx context.Context) ([]*trc.TRC, error)
	// GetCustKey gets the latest signing key and version for the specified customer AS.
	GetCustKey(ctx context.Context, ia addr.IA) (common.RawBytes, uint64, error)
}

// Write contains all write operations fo the trust DB.
type Write interface {
	// InsertIssCert inserts the issuer certificate.
	InsertIssCert(ctx context.Context, crt *cert.Certificate) (int64, error)
	// InsertLeafCert inserts the leaf certificate.
	InsertLeafCert(ctx context.Context, crt *cert.Certificate) (int64, error)
	// InsertChain inserts chain into the database. The first return value is the
	// number of rows affected.
	InsertChain(ctx context.Context, chain *cert.Chain) (int64, error)
	// InsertTRC inserts trcobj into the database. The first return value is the
	// number of rows affected.
	InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error)
	// InsertCustKey inserts or updates the given customer key.
	// If there has been a concurrent insert, i.e. the version in the DB is no longer oldVersion
	// this operation should return an error.
	// If there is no previous version 0 should be passed for the oldVersion argument.
	// If oldVersion == version an error is returned.
	InsertCustKey(ctx context.Context, ia addr.IA, version uint64,
		key common.RawBytes, oldVersion uint64) error
}

// Transaction represents a trust DB transaction with an ongoing transaction.
// To end the transaction either Rollback or Commit should be called. Calling Commit or Rollback
// multiple times will result in an error.
type Transaction interface {
	Read
	Write
	// Commit commits the transaction.
	// Returns the underlying TrustDB connection.
	Commit() error
	// Rollback rollbacks the transaction.
	// Returns the underlying TrustDB connection.
	Rollback() error
}
