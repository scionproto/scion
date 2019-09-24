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
	"database/sql"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrNotFound indicates that the queried value was not found in the database.
	ErrNotFound = serrors.New("not found")
	// ErrHashMismatch indicates that the crypto material exists with a different hash.
	ErrHashMismatch = serrors.New("hash does not match")
)

// DB defines the interface a trust DB must implement.
type DB interface {
	ReadWrite
	// BeginTransaction starts a transaction.
	BeginTransaction(ctx context.Context, opts *sql.TxOptions) (Transaction, error)
	db.LimitSetter
	io.Closer
}

// Transaction represents a trust DB transaction. To end the transaction either
// Rollback or Commit should be called. Calling Commit or Rollback multiple
// times will result in an error.
type Transaction interface {
	ReadWrite
	// Commit commits the transaction.
	Commit() error
	// Rollback rollbacks the transaction.
	Rollback() error
}

// ReadWrite defines the read and write operations.
type ReadWrite interface {
	DBRead
	DBWrite
}

// DBRead defines the read operations.
type DBRead interface {
	TRCRead
	ChainRead
}

// DBWrite defines the write operations.
type DBWrite interface {
	TRCWrite
	ChainWrite
}

// TRCRead defines the TRC read operations.
type TRCRead interface {
	// CompareTRCHash compares the provided hash with the hash in the database.
	// It returns whether the TRC is found in the database and the hash matches.
	// The ErrHashMismatch error is returned if the TRC is in the database and
	// the hash does not match.
	CompareTRCHash(ctx context.Context, isd addr.ISD,
		version scrypto.Version, hash []byte) (bool, error)
	// GetTRC returns the TRC. If it is not found, ErrNotFound is returned.
	GetTRC(ctx context.Context, isd addr.ISD, version scrypto.Version) (*trc.TRC, error)
	// GetRawTRC returns the raw signed TRC bytes. If it is not found,
	// ErrNotFound is returned.
	GetRawTRC(ctx context.Context, isd addr.ISD, version scrypto.Version) ([]byte, error)
	// GetTRCInfo returns the infos for the requested TRC. If it is not found,
	// ErrNotFound is returned.
	GetTRCInfo(ctx context.Context, isd addr.ISD, version scrypto.Version) (TRCInfo, error)
}

// TRCWrite defines the TRC write operations.
type TRCWrite interface {
	// InsertTRC inserts the TRCs. The call returns true if the TRC was
	// inserter, or false if it already existed and the Hash matches.
	InsertTRC(ctx context.Context, decoded DecodedTRC, hash []byte) (bool, error)
}

// ChainRead defines the certificate chain read operations.
type ChainRead interface {
	// GetRawChain returns the raw signed certificate chain bytes. If it is not
	// found, ErrNotFound is returned.
	GetRawChain(ctx context.Context, ia addr.IA, version scrypto.Version) ([]byte, error)
	// CompareASHash compares the provided hash with the hash in the database.
	// It returns whether the AS certificate is found in the database and the
	// hash matches. The ErrHashMismatch error is returned if the AS certificate
	// is in the database and the hash does not match.
	CompareASHash(ctx context.Context, ia addr.IA, version scrypto.Version,
		hash []byte) (bool, error)
	// CompareIssuerHash compares the provided hash with the hash in the
	// database. It returns whether the issuer certificate is found in the
	// database and the hash matches. The ErrHashMismatch error is returned if
	// the issuer certificate is in the database and the hash does not match.
	CompareIssuerHash(ctx context.Context, ia addr.IA,
		version scrypto.Version, hash []byte) (bool, error)
}

// ChainWrite defines the certificate chain write operations.
type ChainWrite interface {
	// InsertChain inserts the certificate chain. The call returns true if the
	// certificate chain was inserted, or false if it already existed and the
	// Hash matches.
	InsertChain(ctx context.Context, decoded DecodedChain, asHash, issHash []byte) (bool, error)
}

// TRCInfo contains metadata about a TRC.
type TRCInfo struct {
	Validity    scrypto.Validity
	GracePeriod time.Duration
	Version     scrypto.Version
}
