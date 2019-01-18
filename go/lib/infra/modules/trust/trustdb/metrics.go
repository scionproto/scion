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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

const (
	promSubsyst = "trustdb"

	promOp     = "op"
	promDBName = "db"
	promError  = "err"

	promOpRead       = "read"
	promOpWrite      = "write"
	promOpBeginTx    = "tx_begin"
	promOpCommitTx   = "tx_commit"
	promOpRollbackTx = "tx_rollback"

	promErrAny     = "err_any"
	promErrTimeout = "err_timeout"
)

var (
	queriesTotal *prometheus.CounterVec
	errorsTotal  *prometheus.CounterVec
)

// InitMetrics prepares the usage of metrics in the trustdb module.
func InitMetrics(namespace string) {
	queriesTotal = prom.NewCounterVec(namespace, promSubsyst, "queries_total",
		"Total queries to the database.", []string{promDBName, promOp})
	errorsTotal = prom.NewCounterVec(namespace, promSubsyst, "errors_total",
		"Amount of trustdb errors.", []string{promDBName, promError})
}

// WithMetrics wraps the given TrustDB into one that also exports metrics.
// InitMetrics must have been called previously, otherwise this method panics.
func WithMetrics(dbName string, trustDB TrustDB) TrustDB {
	return &metricsTrustDB{
		db: trustDB,
		metricsExecutor: &metricsExecutor{
			trustDB: trustDB,
			metrics: newCounters(dbName),
		},
	}
}

type counters struct {
	errAnyTotal       prometheus.Counter
	errTimeoutTotal   prometheus.Counter
	readQueriesTotal  prometheus.Counter
	writeQueriesTotal prometheus.Counter
	beginTxTotal      prometheus.Counter
	commitTxTotal     prometheus.Counter
	rollbackTxTotal   prometheus.Counter
}

func newCounters(dbName string) *counters {
	return &counters{
		errAnyTotal: errorsTotal.With(prometheus.Labels{
			promDBName: dbName,
			promError:  promErrAny,
		}),
		errTimeoutTotal: errorsTotal.With(prometheus.Labels{
			promDBName: dbName,
			promError:  promErrTimeout,
		}),
		readQueriesTotal: queriesTotal.With(prometheus.Labels{
			promDBName: dbName,
			promOp:     promOpRead,
		}),
		writeQueriesTotal: queriesTotal.With(prometheus.Labels{
			promDBName: dbName,
			promOp:     promOpWrite,
		}),
		beginTxTotal: queriesTotal.With(prometheus.Labels{
			promDBName: dbName,
			promOp:     promOpBeginTx,
		}),
		commitTxTotal: queriesTotal.With(prometheus.Labels{
			promDBName: dbName,
			promOp:     promOpCommitTx,
		}),
		rollbackTxTotal: queriesTotal.With(prometheus.Labels{
			promDBName: dbName,
			promOp:     promOpRollbackTx,
		}),
	}
}

type metricsTrustDB struct {
	db TrustDB
	*metricsExecutor
}

func (db *metricsTrustDB) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (Transaction, error) {

	db.metrics.beginTxTotal.Inc()
	tx, err := db.db.BeginTransaction(ctx, opts)
	db.incErr(err)
	if err != nil {
		return nil, err
	}
	return &metricsTransaction{
		tx: tx,
		metricsExecutor: &metricsExecutor{
			trustDB: tx,
			metrics: db.metricsExecutor.metrics,
		},
	}, err
}

func (db *metricsTrustDB) Close() error {
	return db.db.Close()
}

type metricsTransaction struct {
	tx Transaction
	*metricsExecutor
}

func (tx *metricsTransaction) Commit() error {
	tx.metrics.commitTxTotal.Inc()
	err := tx.tx.Commit()
	tx.incErr(err)
	return err
}

func (tx *metricsTransaction) Rollback() error {
	tx.metrics.rollbackTxTotal.Inc()
	err := tx.tx.Rollback()
	tx.incErr(err)
	return err
}

type rwDB interface {
	Read
	Write
}

type metricsExecutor struct {
	trustDB rwDB
	metrics *counters
}

func (db *metricsExecutor) incRead() {
	db.metrics.readQueriesTotal.Inc()
}

func (db *metricsExecutor) incWrite() {
	db.metrics.writeQueriesTotal.Inc()
}

func (db *metricsExecutor) incErr(err error) {
	if err == nil {
		return
	}
	// TODO(lukedirtwalker): categorize error better.
	switch {
	case common.IsTimeoutErr(err):
		db.metrics.errTimeoutTotal.Inc()
	default:
		db.metrics.errAnyTotal.Inc()
	}
}

// below here is very boilerplaty code that implements all DB ops and calls the inc functions.

func (db *metricsExecutor) InsertIssCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	db.incWrite()
	cnt, err := db.trustDB.InsertIssCert(ctx, crt)
	db.incErr(err)
	return cnt, err
}

func (db *metricsExecutor) InsertLeafCert(ctx context.Context,
	crt *cert.Certificate) (int64, error) {

	db.incWrite()
	cnt, err := db.trustDB.InsertLeafCert(ctx, crt)
	db.incErr(err)
	return cnt, err
}

func (db *metricsExecutor) InsertChain(ctx context.Context, chain *cert.Chain) (int64, error) {
	db.incWrite()
	cnt, err := db.trustDB.InsertChain(ctx, chain)
	db.incErr(err)
	return cnt, err
}

func (db *metricsExecutor) InsertTRC(ctx context.Context, trcobj *trc.TRC) (int64, error) {
	db.incWrite()
	cnt, err := db.trustDB.InsertTRC(ctx, trcobj)
	db.incErr(err)
	return cnt, err
}

func (db *metricsExecutor) InsertCustKey(ctx context.Context, ia addr.IA, version uint64,
	key common.RawBytes, oldVersion uint64) error {

	db.incWrite()
	err := db.trustDB.InsertCustKey(ctx, ia, version, key, oldVersion)
	db.incErr(err)
	return err
}

func (db *metricsExecutor) GetIssCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	db.incRead()
	res, err := db.trustDB.GetIssCertVersion(ctx, ia, version)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetIssCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.incRead()
	res, err := db.trustDB.GetIssCertMaxVersion(ctx, ia)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetLeafCertVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Certificate, error) {

	db.incRead()
	res, err := db.trustDB.GetLeafCertVersion(ctx, ia, version)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetLeafCertMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Certificate, error) {

	db.incRead()
	res, err := db.trustDB.GetLeafCertMaxVersion(ctx, ia)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetChainVersion(ctx context.Context, ia addr.IA,
	version uint64) (*cert.Chain, error) {

	db.incRead()
	res, err := db.trustDB.GetChainVersion(ctx, ia, version)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetChainMaxVersion(ctx context.Context,
	ia addr.IA) (*cert.Chain, error) {

	db.incRead()
	res, err := db.trustDB.GetChainMaxVersion(ctx, ia)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetAllChains(ctx context.Context) ([]*cert.Chain, error) {
	db.incRead()
	res, err := db.trustDB.GetAllChains(ctx)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetTRCVersion(ctx context.Context, isd addr.ISD,
	version uint64) (*trc.TRC, error) {

	db.incRead()
	res, err := db.trustDB.GetTRCVersion(ctx, isd, version)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetTRCMaxVersion(ctx context.Context, isd addr.ISD) (*trc.TRC, error) {
	db.incRead()
	res, err := db.trustDB.GetTRCMaxVersion(ctx, isd)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetAllTRCs(ctx context.Context) ([]*trc.TRC, error) {
	db.incRead()
	res, err := db.trustDB.GetAllTRCs(ctx)
	db.incErr(err)
	return res, err
}

func (db *metricsExecutor) GetCustKey(ctx context.Context,
	ia addr.IA) (common.RawBytes, uint64, error) {

	db.incRead()
	res, ver, err := db.trustDB.GetCustKey(ctx, ia)
	db.incErr(err)
	return res, ver, err
}
