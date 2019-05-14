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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/prom"
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

func initMetrics() {
	initMetricsOnce.Do(func() {
		queriesTotal = prom.NewCounterVec(dbNamespace, "", "queries_total",
			"Total queries to the database.", []string{labelDbName, prom.LabelOperation})
		resultsTotal = prom.NewCounterVec(dbNamespace, "", "results_total",
			"Results of trustdb operations.",
			[]string{labelDbName, prom.LabelOperation, prom.LabelResult})
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
	db.metrics.Observe("begin_tx", func() error {
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
		tx: tx,
	}, nil
}

// MetricsTransaction is a wrapper around a beacon db transaction that exports metrics.
type MetricsTransaction struct {
	*executor
	tx Transaction
}

func (tx *MetricsTransaction) Commit() error {
	var err error
	tx.metrics.Observe("tx_commit", func() error {
		err = tx.tx.Commit()
		return err
	})
	return err
}

func (tx *MetricsTransaction) Rollback() error {
	var err error
	tx.metrics.Observe("tx_rollback", func() error {
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

func (c *counters) Observe(op string, action func() error) {
	c.queriesTotal.WithLabelValues(op).Inc()
	err := action()
	c.resultsTotal.WithLabelValues(op, db.ErrToMetricLabel(err)).Inc()
}

type executor struct {
	db      DBReadWrite
	metrics *counters
}

func (e *executor) CandidateBeacons(ctx context.Context, setSize int, usage Usage,
	src addr.IA) (<-chan BeaconOrErr, error) {

	var ret <-chan BeaconOrErr
	var err error
	e.metrics.Observe("candidate_beacons", func() error {
		ret, err = e.db.CandidateBeacons(ctx, setSize, usage, src)
		return err
	})
	return ret, err
}

func (e *executor) BeaconSources(ctx context.Context) ([]addr.IA, error) {
	var ret []addr.IA
	var err error
	e.metrics.Observe("beacon_srcs", func() error {
		ret, err = e.db.BeaconSources(ctx)
		return err
	})
	return ret, err
}

func (e *executor) AllRevocations(ctx context.Context) (<-chan RevocationOrErr, error) {
	var ret <-chan RevocationOrErr
	var err error
	e.metrics.Observe("all_revocations", func() error {
		ret, err = e.db.AllRevocations(ctx)
		return err
	})
	return ret, err
}

func (e *executor) InsertBeacon(ctx context.Context, beacon Beacon, usage Usage) (int, error) {
	var ret int
	var err error
	e.metrics.Observe("insert_beacon", func() error {
		ret, err = e.db.InsertBeacon(ctx, beacon, usage)
		return err
	})
	return ret, err
}

func (e *executor) DeleteExpiredBeacons(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe("delete_expired_beacon", func() error {
		ret, err = e.db.DeleteExpiredBeacons(ctx, now)
		return err
	})
	return ret, err
}

func (e *executor) DeleteRevokedBeacons(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe("delete_revoked_beacons", func() error {
		ret, err = e.db.DeleteRevokedBeacons(ctx, now)
		return err
	})
	return ret, err
}

func (e *executor) InsertRevocation(ctx context.Context,
	revocation *path_mgmt.SignedRevInfo) error {

	var err error
	e.metrics.Observe("insert_revocation", func() error {
		err = e.db.InsertRevocation(ctx, revocation)
		return err
	})
	return err
}

func (e *executor) DeleteRevocation(ctx context.Context, ia addr.IA, ifid common.IFIDType) error {
	var err error
	e.metrics.Observe("delete_revocation", func() error {
		err = e.db.DeleteRevocation(ctx, ia, ifid)
		return err
	})
	return err
}

func (e *executor) DeleteExpiredRevocations(ctx context.Context, now time.Time) (int, error) {
	var ret int
	var err error
	e.metrics.Observe("delete_expired_revocations", func() error {
		ret, err = e.db.DeleteExpiredRevocations(ctx, now)
		return err
	})
	return ret, err
}
