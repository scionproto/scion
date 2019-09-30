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

package trustdb

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

type observer struct {
	driver string
}

func (o observer) Observe(ctx context.Context, op string, action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("trustdb.%s", string(op)))
	defer span.Finish()
	err := action(ctx)
	l := metrics.QueryLabels{
		Driver:    o.driver,
		Operation: op,
		Result:    db.ErrToMetricLabel(err),
	}
	metrics.DB.Queries(l).Inc()
}

var _ (TrustDB) = (*metricsTrustDB)(nil)

type metricsTrustDB struct {
	*metricsExecutor
	// db is only needed to have Close and BeginTransaction methods.
	db TrustDB
}

// WithMetrics wraps the given TrustDB into one that also exports metrics.
func WithMetrics(driver string, trustDB TrustDB) TrustDB {
	rwDBWrapper := &metricsExecutor{
		rwDB: trustDB,
		metrics: observer{
			driver: driver,
		},
	}
	return &metricsTrustDB{
		metricsExecutor: rwDBWrapper,
		db:              trustDB,
	}
}

func (db *metricsTrustDB) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (Transaction, error) {

	var tx Transaction
	var err error
	db.metricsExecutor.metrics.Observe(ctx, metrics.BeginTx, func(ctx context.Context) error {
		tx, err = db.db.BeginTransaction(ctx, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &metricsTransaction{
		tx:  tx,
		ctx: ctx,
		metricsExecutor: &metricsExecutor{
			rwDB:    tx,
			metrics: db.metricsExecutor.metrics,
		},
	}, err
}

func (db *metricsTrustDB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *metricsTrustDB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *metricsTrustDB) Close() error {
	return db.db.Close()
}

var _ (Transaction) = (*metricsTransaction)(nil)

type metricsTransaction struct {
	*metricsExecutor
	// tx is only used for Commit and Rollback.
	tx  Transaction
	ctx context.Context
}

func (tx *metricsTransaction) Commit() error {
	var err error
	tx.metrics.Observe(tx.ctx, metrics.CommitTx, func(_ context.Context) error {
		err = tx.tx.Commit()
		return err
	})
	return err
}

func (tx *metricsTransaction) Rollback() error {
	var err error
	tx.metrics.Observe(tx.ctx, metrics.RollbackTx, func(_ context.Context) error {
		err = tx.tx.Rollback()
		return err
	})
	return err
}

type metricsExecutor struct {
	rwDB    ReadWrite
	metrics observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (db *metricsExecutor) InsertIssCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	var cnt int64
	var err error
	db.metrics.Observe(ctx, metrics.InsertIssCert, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertIssCert(ctx, crt)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {

	var cnt int64
	var err error
	db.metrics.Observe(ctx, metrics.InsertChain, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertChain(ctx, chain)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	var cnt int64
	var err error
	db.metrics.Observe(ctx, metrics.InsertTRC, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertTRC(ctx, trcobj)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertCustKey(ctx context.Context, key *CustKey,
	oldVersion scrypto.Version) error {

	var err error
	db.metrics.Observe(ctx, metrics.InsertCustKey, func(ctx context.Context) error {
		err = db.rwDB.InsertCustKey(ctx, key, oldVersion)
		return err
	})
	return err
}

func (db *metricsExecutor) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version scrypto.Version) (*cert.Certificate, error) {

	var res *cert.Certificate
	var err error
	db.metrics.Observe(ctx, metrics.GetIssCert, func(ctx context.Context) error {
		res, err = db.rwDB.GetIssCertVersion(ctx, ia, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetIssCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	var res *cert.Certificate
	var err error
	db.metrics.Observe(ctx, metrics.GetIssCertMax, func(ctx context.Context) error {
		res, err = db.rwDB.GetIssCertMaxVersion(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllIssCerts(ctx context.Context) (<-chan CertOrErr, error) {
	var res <-chan CertOrErr
	var err error
	db.metrics.Observe(ctx, metrics.GetAllIssCerts, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllIssCerts(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetChainVersion(ctx context.Context, ia addr.IA,
	version scrypto.Version) (*cert.Chain, error) {

	var res *cert.Chain
	var err error
	db.metrics.Observe(ctx, metrics.GetChain, func(ctx context.Context) error {
		res, err = db.rwDB.GetChainVersion(ctx, ia, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetChainMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Chain, error) {

	var res *cert.Chain
	var err error
	db.metrics.Observe(ctx, metrics.GetChainMax, func(ctx context.Context) error {
		res, err = db.rwDB.GetChainMaxVersion(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllChains(ctx context.Context) (<-chan ChainOrErr, error) {
	var res <-chan ChainOrErr
	var err error
	db.metrics.Observe(ctx, metrics.GetAllChains, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllChains(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetTRCVersion(ctx context.Context, isd addr.ISD,
	version scrypto.Version) (*trc.TRC, error) {

	var res *trc.TRC
	var err error
	db.metrics.Observe(ctx, metrics.GetTRC, func(ctx context.Context) error {
		res, err = db.rwDB.GetTRCVersion(ctx, isd, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	var res *trc.TRC
	var err error
	db.metrics.Observe(ctx, metrics.GetTRCMax, func(ctx context.Context) error {
		res, err = db.rwDB.GetTRCMaxVersion(ctx, isd)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllTRCs(ctx context.Context) (<-chan TrcOrErr, error) {
	var res <-chan TrcOrErr
	var err error
	db.metrics.Observe(ctx, metrics.GetAllTRCs, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllTRCs(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetCustKey(ctx context.Context, ia addr.IA) (*CustKey, error) {
	var res *CustKey
	var err error
	db.metrics.Observe(ctx, metrics.GetCustKey, func(ctx context.Context) error {
		res, err = db.rwDB.GetCustKey(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllCustKeys(ctx context.Context) (<-chan CustKeyOrErr, error) {
	var res <-chan CustKeyOrErr
	var err error
	db.metrics.Observe(ctx, metrics.GetAllCustKeys, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllCustKeys(ctx)
		return err
	})
	return res, err
}
