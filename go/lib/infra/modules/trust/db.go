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
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	// ErrNotFound indicates that the queried value was not found in the database.
	ErrNotFound = serrors.New("not found")
	// ErrContentMismatch indicates that the crypto material exists with differing content.
	ErrContentMismatch = serrors.New("content does not match")
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
	// TRCExists returns whether the TRC is found in the database and the
	// content matches. ErrContentMismatch is returned if the TRC is in the
	// database with differing contents.
	TRCExists(ctx context.Context, d decoded.TRC) (bool, error)
	// GetTRC returns the TRC. If it is not found, ErrNotFound is returned.
	GetTRC(ctx context.Context, id TRCID) (*trc.TRC, error)
	// GetRawTRC returns the raw signed TRC bytes. If it is not found,
	// ErrNotFound is returned.
	GetRawTRC(ctx context.Context, id TRCID) ([]byte, error)
	// GetTRCInfo returns the infos for the requested TRC. If it is not found,
	// ErrNotFound is returned.
	GetTRCInfo(ctx context.Context, id TRCID) (TRCInfo, error)
	// GetIssuingGrantKeyInfo returns the infos of the requested AS. If it is
	// not found, ErrNotFound is returned.
	GetIssuingGrantKeyInfo(ctx context.Context, ia addr.IA,
		version scrypto.Version) (KeyInfo, error)
}

// TRCWrite defines the TRC write operations.
type TRCWrite interface {
	// InsertTRC inserts the TRCs. The call returns true if the TRC was
	// inserter, or false if it already existed and the content matches.
	// ErrContentMismatch is returned if the TRC is in the database with
	// differing contents.
	InsertTRC(ctx context.Context, d decoded.TRC) (bool, error)
}

// ChainRead defines the certificate chain read operations.
type ChainRead interface {
	// GetRawChain returns the raw signed certificate chain bytes. If it is not
	// found, ErrNotFound is returned.
	GetRawChain(ctx context.Context, id ChainID) ([]byte, error)
	// ChainExists returns whether the certificate chain is found in the
	// database and the content matches. ErrContentMismatch is returned if any
	// of the two certificates exist in the database with differing contents.
	ChainExists(ctx context.Context, d decoded.Chain) (bool, error)
}

// ChainWrite defines the certificate chain write operations.
type ChainWrite interface {
	// InsertChain inserts the certificate chain. The call returns true in the
	// first return value, if the certificate chain was inserted, or false if it
	// already existed and the contents matches. The second return value
	// indicates whether the issuer certificate was inserted, or it already
	// existed. ErrContentMismatch is returned if any of the two certificates
	// exist in the database with differing contents.
	InsertChain(ctx context.Context, d decoded.Chain) (bool, bool, error)
}

// TRCInfo contains metadata about a TRC.
type TRCInfo struct {
	Validity    scrypto.Validity
	GracePeriod time.Duration
	Version     scrypto.Version
}

// Base indicates if the TRC is a base TRC.
func (i TRCInfo) Base() bool {
	return i.GracePeriod == 0
}

// KeyInfo contains metadata about a primary key.
type KeyInfo struct {
	TRC     TRCInfo
	Version scrypto.KeyVersion
}
