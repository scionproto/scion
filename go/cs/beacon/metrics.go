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

package beacon

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
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/tracing"
)

const (
	dbNamespace = "beacondb"
	labelDbName = "db"
)

var (
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec

	initMetricsOnce sync.Once
)

type dbLabels struct {
	db, op string
}

func (l dbLabels) Labels() []string {
	return []string{labelDbName, prom.LabelOperation}
}

func (l dbLabels) Values() []string {
	return []string{l.db, l.op}
}

type dbLabelsWithResult struct {
	db, op, result string
}

func (l dbLabelsWithResult) Labels() []string {
	return []string{labelDbName, prom.LabelOperation, prom.LabelResult}
}

func (l dbLabelsWithResult) Values() []string {
	return []string{l.db, l.op, l.result}
}

func initMetrics() {
	initMetricsOnce.Do(func() {
		queriesTotal = prom.NewCounterVecWithLabels(dbNamespace, "", "queries_total",
			"Total queries to the database.", dbLabels{})
		resultsTotal = prom.NewCounterVecWithLabels(dbNamespace, "", "results_total",
			"Results of trustdb operations.", dbLabelsWithResult{})
	})
}

// DBWithMetrics wraps the given db into a db that exports metrics.
func DBWithMetrics(dbName string, db DB) *MetricsDB {
	initMetrics()
	return &MetricsDB{
		executor: &executor{
			db:      db,
			metrics: newCounters(dbName),
		},
		db: db,
	}
}

var _ DB = (*MetricsDB)(nil)

// MetricsDB is a wrapper around the beacon db that exports metrics.
type MetricsDB struct {
	*executor
	db DB
}

func (db *MetricsDB) SetMaxOpenConns(maxOpenConns int) {
	db.db.SetMaxOpenConns(maxOpenConns)
}

func (db *MetricsDB) SetMaxIdleConns(maxIdleConns int) {
	db.db.SetMaxIdleConns(maxIdleConns)
}

func (db *MetricsDB) Close() error {
	return db.db.Close()
}

func (db *MetricsDB) BeginTransaction(ctx context.Context,
	opts *sql.TxOptions) (Transaction, error) {

	var tx Transaction
	var err error
	db.metrics.Observe(ctx, "begin_tx", func(ctx context.Context) error {
		tx, err = db.db.BeginTransaction(ctx, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &MetricsTransaction{
		executor: &executor{
			db:      tx,
			metrics: db.metrics,
		},
		tx:  tx,
		ctx: ctx,
	}, nil
}

// MetricsTransaction is a wrapper around a beacon db transaction that exports metrics.
type MetricsTransaction struct {
	*executor
	tx  Transaction
	ctx context.Context
}

func (tx *MetricsTransaction) Commit() error {
	var err error
	tx.metrics.Observe(tx.ctx, "tx_commit", func(_ context.Context) error {
		err = tx.tx.Commit()
		return err
	})
	return err
}

func (tx *MetricsTransaction) Rollback() error {
	var err error
	tx.metrics.Observe(tx.ctx, "tx_rollback", func(_ context.Context) error {
		err = tx.tx.Rollback()
		if err == sql.ErrTxDone {
			return nil
		}
		return err
	})
	return err
}

type counters struct {
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec
}

func newCounters(dbName string) *counters {
	labels := prometheus.Labels{labelDbName: dbName}
	return &counters{
		queriesTotal: queriesTotal.MustCurryWith(labels),
		resultsTotal: resultsTotal.MustCurryWith(labels),
	}
}

func (c *counters) Observe(ctx context.Context, op string, action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("beacondb.%s", op))
	defer span.Finish()
	c.queriesTotal.WithLabelValues(op).Inc()
	err := action(ctx)

	label := db.ErrToMetricLabel(err)
	ext.Error.Set(span, err != nil)
	tracing.ResultLabel(span, label)

	c.resultsTotal.WithLabelValues(op, label).Inc()
}

type executor struct {
	db      DBReadWrite
	metrics *counters
}

func (e *executor) CandidateBeacons(ctx context.Context, setSize int, usage Usage,
	src addr.IA) (<-chan BeaconOrErr, error) {

	var ret <-chan BeaconOrErr
	var err error
	e.metrics.Observe(ctx, "candidate_beacons", func(ctx context.Context) error {
		ret, err = e.db.CandidateBeacons(ctx, setSize, usage, src)
		return err
	})
	return ret, err
}

func (e *executor) BeaconSources(ctx context.Context) ([]addr.IA, error) {
	var ret []addr.IA
	var err error
	e.metrics.Observe(ctx, "beacon_srcs", func(ctx context.Context) error {
		ret, err = e.db.BeaconSources(ctx)
		return err
	})
	return ret, err
}

func (e *executor) AllRevocations(ctx context.Context) (<-chan RevocationOrErr, error) {
	var ret <-chan RevocationOrErr
	var err error
	e.metrics.Observe(ctx, "all_revocations", func(ctx context.Context) error {
		ret, err = e.db.AllRevocations(ctx)
		return err
	})
	return ret, err
}

func (e *executor) InsertBeacon(ctx context.Context, beacon Beacon,
	usage Usage) (InsertStats, error) {
	var ret InsertStats
	var err error
	e.metrics.Observe(ctx, "insert_beacon", func(ctx context.Context) error {
		ret, err = e.db.InsertBeacon(ctx, beacon, usage)
		return err
	})
	return ret, err
}

func (e *executor) DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe(ctx, "delete_expired_beacon", func(ctx context.Context) error {
		ret, err = e.db.DeleteExpiredBeacons(ctx, now)
		return err
	})
	return ret, err
}

func (e *executor) DeleteRevokedBeacons(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe(ctx, "delete_revoked_beacons", func(ctx context.Context) error {
		ret, err = e.db.DeleteRevokedBeacons(ctx, now)
		return err
	})
	return ret, err
}

func (e *executor) InsertRevocation(ctx context.Context,
	revocation *path_mgmt.SignedRevInfo) error {

	var err error
	e.metrics.Observe(ctx, "insert_revocation", func(ctx context.Context) error {
		err = e.db.InsertRevocation(ctx, revocation)
		return err
	})
	return err
}

func (e *executor) DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error {
	var err error
	e.metrics.Observe(ctx, "delete_revocation", func(ctx context.Context) error {
		err = e.db.DeleteRevocation(ctx, ia, ifid)
		return err
	})
	return err
}

func (e *executor) DeleteExpiredRevocations(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe(ctx, "delete_expired_revocations", func(ctx context.Context) error {
		ret, err = e.db.DeleteExpiredRevocations(ctx, now)
		return err
	})
	return ret, err
}
