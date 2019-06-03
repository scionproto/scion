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
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

const (
	promNamespace = "trustdb"

	promDBName = "db"
)

type promOp string

const (
	promOpGetIssCert     promOp = "get_iss_cert"
	promOpGetIssCertMV   promOp = "get_iss_cert_mv"
	promOpGetAllIssCerts promOp = "get_all_iss_certs"
	promOpGetChain       promOp = "get_chain"
	promOpGetChainMV     promOp = "get_chain_mv"
	promOpGetAllChains   promOp = "get_all_chains"
	promOpGetTRC         promOp = "get_trc"
	promOpGetTRCMV       promOp = "get_trc_mv"
	promOpGetAllTRCs     promOp = "get_all_trcs"
	promOpGetCustKey     promOp = "get_cust_key"
	promOpGetAllCustKeys promOp = "get_all_cust_keys"

	promOpInsertIssCert promOp = "insert_iss_cert"
	promOpInsertChain   promOp = "insert_chain"
	promOpInsertTRC     promOp = "insert_trc"
	promOpInsertCustKey promOp = "insert_cust_key"

	promOpBeginTx    promOp = "tx_begin"
	promOpCommitTx   promOp = "tx_commit"
	promOpRollbackTx promOp = "tx_rollback"
)

var (
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec

	initMetricsOnce sync.Once
)

func initMetrics() {
	initMetricsOnce.Do(func() {
		// Cardinality: X (dbName) * 18 (len(all ops))
		queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
			"Total queries to the database.", []string{promDBName, prom.LabelOperation})
		// Cardinality: X (dbName) * 18 (len(all ops)) * Y (len(all results))
		resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
			"Results of trustdb operations.",
			[]string{promDBName, prom.LabelOperation, prom.LabelResult})
	})
}

// WithMetrics wraps the given TrustDB into one that also exports metrics.
func WithMetrics(dbName string, trustDB TrustDB) TrustDB {
	initMetrics()
	metricsCounters := newCounters(dbName)
	rwDBWrapper := &metricsExecutor{
		rwDB:    trustDB,
		metrics: metricsCounters,
	}
	return &metricsTrustDB{
		metricsExecutor: rwDBWrapper,
		db:              trustDB,
	}
}

type counters struct {
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec
}

func newCounters(dbName string) *counters {
	labels := prometheus.Labels{promDBName: dbName}
	return &counters{
		queriesTotal: queriesTotal.MustCurryWith(labels),
		resultsTotal: resultsTotal.MustCurryWith(labels),
	}
}

func (c *counters) Observe(ctx context.Context, op promOp, action func(ctx context.Context) error) {
	c.queriesTotal.WithLabelValues(string(op)).Inc()
	err := action(ctx)
	c.resultsTotal.WithLabelValues(string(op), db.ErrToMetricLabel(err))
}

var _ (TrustDB) = (*metricsTrustDB)(nil)

type metricsTrustDB struct {
	*metricsExecutor
	// db is only needed to have Close and BeginTransaction methods.
	db TrustDB
}

func (db *metricsTrustDB) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (Transaction, error) {

	var tx Transaction
	var err error
	db.metricsExecutor.metrics.Observe(ctx, promOpBeginTx, func(ctx context.Context) error {
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
	tx.metrics.Observe(tx.ctx, promOpCommitTx, func(_ context.Context) error {
		err = tx.tx.Commit()
		return err
	})
	return err
}

func (tx *metricsTransaction) Rollback() error {
	var err error
	tx.metrics.Observe(tx.ctx, promOpRollbackTx, func(_ context.Context) error {
		err = tx.tx.Rollback()
		return err
	})
	return err
}

type metricsExecutor struct {
	rwDB    ReadWrite
	metrics *counters
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (db *metricsExecutor) InsertIssCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	var cnt int64
	var err error
	db.metrics.Observe(ctx, promOpInsertIssCert, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertIssCert(ctx, crt)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {

	var cnt int64
	var err error
	db.metrics.Observe(ctx, promOpInsertChain, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertChain(ctx, chain)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	var cnt int64
	var err error
	db.metrics.Observe(ctx, promOpInsertTRC, func(ctx context.Context) error {
		cnt, err = db.rwDB.InsertTRC(ctx, trcobj)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertCustKey(ctx context.Context, key *CustKey,
	oldVersion uint64) error {

	var err error
	db.metrics.Observe(ctx, promOpInsertCustKey, func(ctx context.Context) error {
		err = db.rwDB.InsertCustKey(ctx, key, oldVersion)
		return err
	})
	return err
}

func (db *metricsExecutor) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	var res *cert.Certificate
	var err error
	db.metrics.Observe(ctx, promOpGetIssCert, func(ctx context.Context) error {
		res, err = db.rwDB.GetIssCertVersion(ctx, ia, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetIssCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	var res *cert.Certificate
	var err error
	db.metrics.Observe(ctx, promOpGetIssCertMV, func(ctx context.Context) error {
		res, err = db.rwDB.GetIssCertMaxVersion(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllIssCerts(ctx context.Context) (<-chan CertOrErr, error) {
	var res <-chan CertOrErr
	var err error
	db.metrics.Observe(ctx, promOpGetAllIssCerts, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllIssCerts(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetChainVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	var res *cert.Chain
	var err error
	db.metrics.Observe(ctx, promOpGetChain, func(ctx context.Context) error {
		res, err = db.rwDB.GetChainVersion(ctx, ia, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetChainMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Chain, error) {

	var res *cert.Chain
	var err error
	db.metrics.Observe(ctx, promOpGetChainMV, func(ctx context.Context) error {
		res, err = db.rwDB.GetChainMaxVersion(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllChains(ctx context.Context) (<-chan ChainOrErr, error) {
	var res <-chan ChainOrErr
	var err error
	db.metrics.Observe(ctx, promOpGetAllChains, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllChains(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetTRCVersion(ctx context.Context, isd addr.ISD,
	version uint64) (*trc.TRC, error) {

	var res *trc.TRC
	var err error
	db.metrics.Observe(ctx, promOpGetTRC, func(ctx context.Context) error {
		res, err = db.rwDB.GetTRCVersion(ctx, isd, version)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	var res *trc.TRC
	var err error
	db.metrics.Observe(ctx, promOpGetTRCMV, func(ctx context.Context) error {
		res, err = db.rwDB.GetTRCMaxVersion(ctx, isd)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllTRCs(ctx context.Context) (<-chan TrcOrErr, error) {
	var res <-chan TrcOrErr
	var err error
	db.metrics.Observe(ctx, promOpGetAllTRCs, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllTRCs(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetCustKey(ctx context.Context, ia addr.IA) (*CustKey, error) {
	var res *CustKey
	var err error
	db.metrics.Observe(ctx, promOpGetCustKey, func(ctx context.Context) error {
		res, err = db.rwDB.GetCustKey(ctx, ia)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAllCustKeys(ctx context.Context) (<-chan CustKeyOrErr, error) {
	var res <-chan CustKeyOrErr
	var err error
	db.metrics.Observe(ctx, promOpGetAllCustKeys, func(ctx context.Context) error {
		res, err = db.rwDB.GetAllCustKeys(ctx)
		return err
	})
	return res, err
}
