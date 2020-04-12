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

package pathdb

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/tracing"
)

const (
	promNamespace = "pathdb"

	promDBName = "db"
)

type promOp string

const (
	promOpInsert          promOp = "insert"
	promOpInsertHpCfg     promOp = "insert_with_hpcfg"
	promOpDelete          promOp = "delete"
	promOpDeleteExpired   promOp = "delete_expired"
	promOpGet             promOp = "get"
	promOpGetAll          promOp = "get_all"
	promOpInsertNextQuery promOp = "insert_next_query"
	promOpGetNextQuery    promOp = "get_next_query"
	promOpDeleteExpiredNQ promOp = "delete_expired_nq"
	promOpDeleteNQ        promOp = "delete_nq"

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
		// Cardinality: X (dbName) * 13 (len(all ops))
		queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
			"Total queries to the database.", []string{promDBName, prom.LabelOperation})
		// Cardinality: X (dbNmae) * 13 (len(all ops)) * Y (len(all results))
		resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
			"The results of the pathdb ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

// WithMetrics wraps the given PathDB into one that also exports metrics.
// dbName will be added as a label to all metrics, so that multiple path DBs can be differentiated.
func WithMetrics(dbName string, pathDB PathDB) PathDB {
	initMetrics()
	labels := prometheus.Labels{promDBName: dbName}
	return &metricsPathDB{
		metricsExecutor: &metricsExecutor{
			pathDB: pathDB,
			metrics: &counters{
				queriesTotal: queriesTotal.MustCurryWith(labels),
				resultsTotal: resultsTotal.MustCurryWith(labels),
			},
		},
		db: pathDB,
	}
}

type counters struct {
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec
}

func (c *counters) Observe(ctx context.Context, op promOp, action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("pathdb.%s", string(op)))
	defer span.Finish()
	c.queriesTotal.WithLabelValues(string(op)).Inc()
	err := action(ctx)

	label := db.ErrToMetricLabel(err)
	ext.Error.Set(span, err != nil)
	tracing.ResultLabel(span, label)

	c.resultsTotal.WithLabelValues(label, string(op)).Inc()
}

var _ (PathDB) = (*metricsPathDB)(nil)

// metricsPathDB is a PathDB wrapper that exports the counts of operations as prometheus metrics.
type metricsPathDB struct {
	*metricsExecutor
	// db is only needed to have BeginTransaction method.
	db PathDB
}

func (db *metricsPathDB) Close() error {
	return db.db.Close()
}

func (db *metricsPathDB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}
func (db *metricsPathDB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *metricsPathDB) BeginTransaction(ctx context.Context,
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
			pathDB:  tx,
			metrics: db.metricsExecutor.metrics,
		},
	}, err
}

var _ (Transaction) = (*metricsTransaction)(nil)

type metricsTransaction struct {
	*metricsExecutor
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
		if err == sql.ErrTxDone {
			return nil
		}
		return err
	})
	return err
}

var _ (ReadWrite) = (*metricsExecutor)(nil)

type metricsExecutor struct {
	pathDB  ReadWrite
	metrics *counters
}

func (db *metricsExecutor) Insert(ctx context.Context, meta *seg.Meta) (InsertStats, error) {
	var cnt InsertStats
	var err error
	db.metrics.Observe(ctx, promOpInsert, func(ctx context.Context) error {
		cnt, err = db.pathDB.Insert(ctx, meta)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) InsertWithHPCfgIDs(ctx context.Context,
	meta *seg.Meta, hpCfgIds []*query.HPCfgID) (InsertStats, error) {

	var cnt InsertStats
	var err error
	db.metrics.Observe(ctx, promOpInsertHpCfg, func(ctx context.Context) error {
		cnt, err = db.pathDB.InsertWithHPCfgIDs(ctx, meta, hpCfgIds)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) Delete(ctx context.Context, params *query.Params) (int, error) {
	var cnt int
	var err error
	db.metrics.Observe(ctx, promOpDelete, func(ctx context.Context) error {
		cnt, err = db.pathDB.Delete(ctx, params)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	var cnt int
	var err error
	db.metrics.Observe(ctx, promOpDeleteExpired, func(ctx context.Context) error {
		cnt, err = db.pathDB.DeleteExpired(ctx, now)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) Get(ctx context.Context, params *query.Params) (query.Results, error) {
	var res query.Results
	var err error
	db.metrics.Observe(ctx, promOpGet, func(ctx context.Context) error {
		res, err = db.pathDB.Get(ctx, params)
		return err
	})
	return res, err
}

func (db *metricsExecutor) GetAll(ctx context.Context) (<-chan query.ResultOrErr, error) {
	var res <-chan query.ResultOrErr
	var err error
	db.metrics.Observe(ctx, promOpGetAll, func(ctx context.Context) error {
		res, err = db.pathDB.GetAll(ctx)
		return err
	})
	return res, err
}

func (db *metricsExecutor) InsertNextQuery(ctx context.Context,
	src, dst addr.IA, policy PolicyHash, nextQuery time.Time) (bool, error) {

	var ok bool
	var err error
	db.metrics.Observe(ctx, promOpInsertNextQuery, func(ctx context.Context) error {
		ok, err = db.pathDB.InsertNextQuery(ctx, src, dst, policy, nextQuery)
		return err
	})
	return ok, err
}

func (db *metricsExecutor) GetNextQuery(ctx context.Context, src, dst addr.IA,
	policy PolicyHash) (time.Time, error) {

	var t time.Time
	var err error
	db.metrics.Observe(ctx, promOpGetNextQuery, func(ctx context.Context) error {
		t, err = db.pathDB.GetNextQuery(ctx, src, dst, policy)
		return err
	})
	return t, err
}

func (db *metricsExecutor) DeleteExpiredNQ(ctx context.Context, now time.Time) (int, error) {
	var cnt int
	var err error
	db.metrics.Observe(ctx, promOpDeleteExpiredNQ, func(ctx context.Context) error {
		cnt, err = db.pathDB.DeleteExpiredNQ(ctx, now)
		return err
	})
	return cnt, err
}

func (db *metricsExecutor) DeleteNQ(ctx context.Context, src, dst addr.IA,
	policy PolicyHash) (int, error) {

	var cnt int
	var err error
	db.metrics.Observe(ctx, promOpDeleteNQ, func(ctx context.Context) error {
		cnt, err = db.pathDB.DeleteNQ(ctx, src, dst, policy)
		return err
	})
	return cnt, err
}
