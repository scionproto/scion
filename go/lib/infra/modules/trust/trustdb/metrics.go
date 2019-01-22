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
	"github.com/scionproto/scion/go/lib/common"
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
	promOpGetIssCert    promOp = "get_iss_cert"
	promOpGetIssCertMV  promOp = "get_iss_cert_mv"
	promOpGetLeafCert   promOp = "get_leaf_cert"
	promOpGetLeafCertMV promOp = "get_leaf_cert_mv"
	promOpGetChain      promOp = "get_chain"
	promOpGetChainMV    promOp = "get_chain_mv"
	promOpGetAllChains  promOp = "get_all_chains"
	promOpGetTRC        promOp = "get_trc"
	promOpGetTRCMV      promOp = "get_trc_mv"
	promOpGetAllTRCs    promOp = "get_all_trcs"
	promOpGetCustKey    promOp = "get_cust_key"

	promOpInsertIssCert  promOp = "insert_iss_cert"
	promOpInsertLeafCert promOp = "insert_leaf_cert"
	promOpInsertChain    promOp = "insert_chain"
	promOpInsertTRC      promOp = "insert_trc"
	promOpInsertCustKey  promOp = "insert_cust_key"

	promOpBeginTx    promOp = "tx_begin"
	promOpCommitTx   promOp = "tx_commit"
	promOpRollbackTx promOp = "tx_rollback"
)

var (
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec

	allOps = []promOp{
		promOpGetIssCert,
		promOpGetIssCertMV,
		promOpGetLeafCert,
		promOpGetLeafCertMV,
		promOpGetChain,
		promOpGetChainMV,
		promOpGetAllChains,
		promOpGetTRC,
		promOpGetTRCMV,
		promOpGetAllTRCs,
		promOpGetCustKey,

		promOpInsertIssCert,
		promOpInsertLeafCert,
		promOpInsertChain,
		promOpInsertTRC,
		promOpInsertCustKey,

		promOpBeginTx,
		promOpCommitTx,
		promOpRollbackTx,
	}

	allResults = []string{
		prom.ResultOk,
		prom.ErrNotClassified,
		prom.ErrTimeout,
	}

	initMetricsOnce sync.Once
)

func initMetrics() {
	initMetricsOnce.Do(func() {
		// Cardinality: X (dbName) * 19 (len(allOps))
		queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
			"Total queries to the database.", []string{promDBName, prom.LabelOperation})
		// Cardinality: X (dbName) * 19 (len(allOps)) * 3 (len(allResults))
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
	opCounters     map[promOp]prometheus.Counter
	resultCounters map[promOp]map[string]prometheus.Counter
}

func newCounters(dbName string) *counters {
	return &counters{
		opCounters:     opCounters(dbName),
		resultCounters: resultCounters(dbName),
	}
}

func opCounters(dbName string) map[promOp]prometheus.Counter {
	opCounters := make(map[promOp]prometheus.Counter)
	for _, op := range allOps {
		opCounters[op] = queriesTotal.With(prometheus.Labels{
			promDBName:          dbName,
			prom.LabelOperation: string(op),
		})
	}
	return opCounters
}

func resultCounters(dbName string) map[promOp]map[string]prometheus.Counter {
	resultCounters := make(map[promOp]map[string]prometheus.Counter)
	for _, op := range allOps {
		resultCounters[op] = make(map[string]prometheus.Counter)
		for _, res := range allResults {
			resultCounters[op][res] = resultsTotal.With(prometheus.Labels{
				promDBName:          dbName,
				prom.LabelOperation: string(op),
				prom.LabelResult:    res,
			})
		}
	}
	return resultCounters
}

func (c *counters) incOp(op promOp) {
	c.opCounters[op].Inc()
}

func (c *counters) incResult(op promOp, err error) {
	// TODO(lukedirtwalker): categorize error better.
	switch {
	case err == nil:
		c.resultCounters[op][prom.ResultOk].Inc()
	case common.IsTimeoutErr(err):
		c.resultCounters[op][prom.ErrTimeout].Inc()
	default:
		c.resultCounters[op][prom.ErrNotClassified].Inc()
	}
}

var _ (TrustDB) = (*metricsTrustDB)(nil)

type metricsTrustDB struct {
	*metricsExecutor
	// db is only needed to have Close and BeginTransaction methods.
	db TrustDB
}

func (db *metricsTrustDB) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (Transaction, error) {

	db.metricsExecutor.metrics.incOp(promOpBeginTx)
	tx, err := db.db.BeginTransaction(ctx, opts)
	db.metricsExecutor.metrics.incResult(promOpBeginTx, err)
	if err != nil {
		return nil, err
	}
	return &metricsTransaction{
		tx: tx,
		metricsExecutor: &metricsExecutor{
			rwDB:    tx,
			metrics: db.metricsExecutor.metrics,
		},
	}, err
}

func (db *metricsTrustDB) Close() error {
	return db.db.Close()
}

var _ (Transaction) = (*metricsTransaction)(nil)

type metricsTransaction struct {
	*metricsExecutor
	// tx is only used for Commit and Rollback.
	tx Transaction
}

func (tx *metricsTransaction) Commit() error {
	tx.metrics.incOp(promOpCommitTx)
	err := tx.tx.Commit()
	tx.metrics.incResult(promOpCommitTx, err)
	return err
}

func (tx *metricsTransaction) Rollback() error {
	tx.metrics.incOp(promOpRollbackTx)
	err := tx.tx.Rollback()
	tx.metrics.incResult(promOpRollbackTx, err)
	return err
}

type metricsExecutor struct {
	rwDB    ReadWrite
	metrics *counters
}

// below here is very boilerplaty code that implements all DB ops and calls the inc functions.

func (db *metricsExecutor) InsertIssCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	db.metrics.incOp(promOpInsertIssCert)
	cnt, err := db.rwDB.InsertIssCert(ctx, crt)
	db.metrics.incResult(promOpInsertIssCert, err)
	return cnt, err
}

func (db *metricsExecutor) InsertLeafCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	db.metrics.incOp(promOpInsertLeafCert)
	cnt, err := db.rwDB.InsertLeafCert(ctx, crt)
	db.metrics.incResult(promOpInsertLeafCert, err)
	return cnt, err
}

func (db *metricsExecutor) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {
	db.metrics.incOp(promOpInsertChain)
	cnt, err := db.rwDB.InsertChain(ctx, chain)
	db.metrics.incResult(promOpInsertChain, err)
	return cnt, err
}

func (db *metricsExecutor) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	db.metrics.incOp(promOpInsertTRC)
	cnt, err := db.rwDB.InsertTRC(ctx, trcobj)
	db.metrics.incResult(promOpInsertTRC, err)
	return cnt, err
}

func (db *metricsExecutor) InsertCustKey(ctx context.Context, ia addr.IA, version uint64,
	key common.RawBytes, oldVersion uint64) error {

	db.metrics.incOp(promOpInsertCustKey)
	err := db.rwDB.InsertCustKey(ctx, ia, version, key, oldVersion)
	db.metrics.incResult(promOpInsertCustKey, err)
	return err
}

func (db *metricsExecutor) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	db.metrics.incOp(promOpGetIssCert)
	res, err := db.rwDB.GetIssCertVersion(ctx, ia, version)
	db.metrics.incResult(promOpGetIssCert, err)
	return res, err
}

func (db *metricsExecutor) GetIssCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.metrics.incOp(promOpGetIssCertMV)
	res, err := db.rwDB.GetIssCertMaxVersion(ctx, ia)
	db.metrics.incResult(promOpGetIssCertMV, err)
	return res, err
}

func (db *metricsExecutor) GetLeafCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	db.metrics.incOp(promOpGetLeafCert)
	res, err := db.rwDB.GetLeafCertVersion(ctx, ia, version)
	db.metrics.incResult(promOpGetLeafCert, err)
	return res, err
}

func (db *metricsExecutor) GetLeafCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.metrics.incOp(promOpGetLeafCertMV)
	res, err := db.rwDB.GetLeafCertMaxVersion(ctx, ia)
	db.metrics.incResult(promOpGetLeafCertMV, err)
	return res, err
}

func (db *metricsExecutor) GetChainVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	db.metrics.incOp(promOpGetChain)
	res, err := db.rwDB.GetChainVersion(ctx, ia, version)
	db.metrics.incResult(promOpGetChain, err)
	return res, err
}

func (db *metricsExecutor) GetChainMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Chain, error) {

	db.metrics.incOp(promOpGetChainMV)
	res, err := db.rwDB.GetChainMaxVersion(ctx, ia)
	db.metrics.incResult(promOpGetChainMV, err)
	return res, err
}

func (db *metricsExecutor) GetAllChains(ctx context.Context) ([]*cert.Chain, error) {
	db.metrics.incOp(promOpGetAllChains)
	res, err := db.rwDB.GetAllChains(ctx)
	db.metrics.incResult(promOpGetAllChains, err)
	return res, err
}

func (db *metricsExecutor) GetTRCVersion(ctx context.Context, isd addr.ISD,
	version uint64) (*trc.TRC, error) {

	db.metrics.incOp(promOpGetTRC)
	res, err := db.rwDB.GetTRCVersion(ctx, isd, version)
	db.metrics.incResult(promOpGetTRC, err)
	return res, err
}

func (db *metricsExecutor) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	db.metrics.incOp(promOpGetTRCMV)
	res, err := db.rwDB.GetTRCMaxVersion(ctx, isd)
	db.metrics.incResult(promOpGetTRCMV, err)
	return res, err
}

func (db *metricsExecutor) GetAllTRCs(ctx context.Context) ([]*trc.TRC, error) {
	db.metrics.incOp(promOpGetAllTRCs)
	res, err := db.rwDB.GetAllTRCs(ctx)
	db.metrics.incResult(promOpGetAllTRCs, err)
	return res, err
}

func (db *metricsExecutor) GetCustKey(ctx context.Context,
	ia addr.IA) (common.RawBytes, uint64, error) {

	db.metrics.incOp(promOpGetCustKey)
	res, ver, err := db.rwDB.GetCustKey(ctx, ia)
	db.metrics.incResult(promOpGetCustKey, err)
	return res, ver, err
}
