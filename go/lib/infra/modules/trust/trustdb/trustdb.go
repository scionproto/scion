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
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

// TrustDB is a database containing Certificates, Chains and TRCs, stored in JSON format.
// TrustDB is the interface that all trust databases have to implement.
// Read and Write interactions with this interface have to happen in individual transactions
// (either explicit or implicit).
type TrustDB interface {
	ReadWrite
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	db.LimitSetter
	io.Closer
}

// CertOrErr contains a certificate or an error.
type CertOrErr struct {
	Cert *cert.Certificate
	Err  error
}

// ChainOrErr contains a chain or an error.
type ChainOrErr struct {
	Chain *cert.Chain
	Err   error
}

// TrcOrErr contains a TRC or an error.
type TrcOrErr struct {
	TRC *trc.TRC
	Err error
}

// CustKey contains a customer key and the meta information (customer IA and the version).
type CustKey struct {
	IA      addr.IA
	Key     common.RawBytes
	Version uint64
}

// CustKeyOrErr contains a customer key or an error.
type CustKeyOrErr struct {
	CustKey *CustKey
	Err     error
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
	// GetAllIssCerts returns a channel that will provide all issuer certs in the trust db. If the
	// trust db can't prepare the query a nil channel an the error is returned. If the querying
	// succeeded the channel will be filled with issuer certs in the db. If an error occurs during
	// the reading an error is pushed in the channel and the operation is immediately aborted, that
	// means the result might be incomplete. Note that the implementation can spawn a goroutine to
	// fill the channel, therefore the channel must be fully drained to guarantee destruction of the
	// goroutine.
	GetAllIssCerts(ctx context.Context) (<-chan CertOrErr, error)
	// GetChainVersion returns the specified version of the certificate chain for
	// ia. If version is scrypto.LatestVer, this is equivalent to GetChainMaxVersion.
	GetChainVersion(ctx context.Context, ia addr.IA, version uint64) (*cert.Chain, error)
	// GetChainMaxVersion returns the max version of the chain for ia.
	GetChainMaxVersion(ctx context.Context, ia addr.IA) (*cert.Chain, error)
	// GetAllChains returns a channel that will provide all chains in the trust db. If the trust db
	// can't prepare the query a nil channel an the error is returned. If the querying succeeded the
	// channel will be filled with chains in the db. If an error occurs during the reading an error
	// is pushed in the channel and the operation is immediately aborted, that means the result
	// might be incomplete. Note that the implementation can spawn a goroutine to fill the channel,
	// therefore the channel must be fully drained to guarantee destruction of the goroutine.
	GetAllChains(ctx context.Context) (<-chan ChainOrErr, error)
	// GetTRCVersion returns the specified version of the TRC for
	// isd. If version is scrypto.LatestVer, this is equivalent to GetTRCMaxVersion.
	GetTRCVersion(ctx context.Context, isd addr.ISD, version uint64) (*trc.TRC, error)
	// GetTRCMaxVersion returns the max version of the TRC for ia.
	GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error)
	// GetAllTRCs returns a channel that will provide all TRCs in the trust db. If the trust db
	// can't prepare the query a nil channel an the error is returned. If the querying succeeded the
	// channel will be filled with TRCs in the db. If an error occurs during the reading an error is
	// pushed in the channel and the operation is immediately aborted, that means the result might
	// be incomplete. Note that the implementation can spawn a goroutine to fill the channel,
	// therefore the channel must be fully drained to guarantee destruction of the goroutine.
	GetAllTRCs(ctx context.Context) (<-chan TrcOrErr, error)
	// GetCustKey gets the latest signing key and version for the specified customer AS.
	GetCustKey(ctx context.Context, ia addr.IA) (*CustKey, error)
	// GetAllCustKeys returns a channel that will provide all customer keys in the trust db. If the
	// trust db can't prepare the query a nil channel an the error is returned. If the querying
	// succeeded the channel will be filled with customer keys in the db. If an error occurs during
	// the reading an error is pushed in the channel and the operation is immediately aborted, that
	// means the result might be incomplete. Note that the implementation can spawn a goroutine to
	// fill the channel, therefore the channel must be fully drained to guarantee destruction of the
	// goroutine.
	GetAllCustKeys(ctx context.Context) (<-chan CustKeyOrErr, error)
}

// Write contains all write operations fo the trust DB.
type Write interface {
	// InsertIssCert inserts the issuer certificate.
	InsertIssCert(ctx context.Context, crt *cert.Certificate) (int64, error)
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
	InsertCustKey(ctx context.Context, key *CustKey, oldVersion uint64) error
}

// ReadWrite contains all read and write operations of the trust DB.
type ReadWrite interface {
	Read
	Write
}

// Transaction represents a trust DB transaction with an ongoing transaction.
// To end the transaction either Rollback or Commit should be called. Calling Commit or Rollback
// multiple times will result in an error.
type Transaction interface {
	ReadWrite
	// Commit commits the transaction.
	Commit() error
	// Rollback rollbacks the transaction.
	Rollback() error
}
