// Copyright 2021 ETH Zurich
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

package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/prom"
	dblib "github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/tracing"
)

const (
	svNamespace = "secretValueDB"
	promDBName  = "db"
)

type promOp string

const (
	promOpGetSV           promOp = "get_sv"
	promOpInsertSV        promOp = "insert_sv"
	promOpDeleteExpiredSV promOp = "delete_experied_sv"
)

var (
	queriesSVTotal *prometheus.CounterVec
	resultsSVTotal *prometheus.CounterVec

	initMetricsSVOnce sync.Once
)

func initMetricsSecretValue() {
	initMetricsSVOnce.Do(func() {
		queriesSVTotal = prom.NewCounterVec(svNamespace, "", "queries_total",
			"Total queries to the SecretValueDB.", []string{promDBName, prom.LabelOperation})
		resultsSVTotal = prom.NewCounterVec(svNamespace, "", "results_total",
			"The results of the SecretValueDB ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

// SecretValueWithMetrics wraps the given SecretValueDB into one that also exports metrics.
func SecretValueWithMetrics(dbName string, svdb drkey.SecretValueDB) drkey.SecretValueDB {
	initMetricsSecretValue()
	labels := prometheus.Labels{promDBName: dbName}
	return &MetricsDB{
		db: svdb,
		metrics: &countersSV{
			queriesSVTotal: queriesSVTotal.MustCurryWith(labels),
			resultsSVTotal: resultsSVTotal.MustCurryWith(labels),
		},
	}
}

type countersSV struct {
	queriesSVTotal *prometheus.CounterVec
	resultsSVTotal *prometheus.CounterVec
}

func (c *countersSV) Observe(ctx context.Context, op promOp,
	action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeySVDB.%s", string(op)))
	defer span.Finish()
	c.queriesSVTotal.WithLabelValues(string(op)).Inc()
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	c.resultsSVTotal.WithLabelValues(label, string(op)).Inc()
}

var _ drkey.SecretValueDB = (*MetricsDB)(nil)

// MetricsDB is a SecretValueDB wrapper that exports the counts of operations as
// prometheus metrics
type MetricsDB struct {
	db      drkey.SecretValueDB
	metrics *countersSV
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

func (db *MetricsDB) GetValue(ctx context.Context,
	meta drkey.SecretValueMeta, asSecret []byte) (drkey.SecretValue, error) {
	var ret drkey.SecretValue
	var err error
	db.metrics.Observe(ctx, promOpGetSV, func(ctx context.Context) error {
		ret, err = db.db.GetValue(ctx, meta, asSecret)
		return err
	})
	return ret, err
}

func (db *MetricsDB) InsertValue(ctx context.Context,
	proto drkey.Protocol, epoch drkey.Epoch) error {
	var err error
	db.metrics.Observe(ctx, promOpInsertSV, func(ctx context.Context) error {
		err = db.db.InsertValue(ctx, proto, epoch)
		return err
	})
	return err
}

func (db *MetricsDB) DeleteExpiredValues(ctx context.Context,
	cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.metrics.Observe(ctx, promOpDeleteExpiredSV, func(ctx context.Context) error {
		ret, err = db.db.DeleteExpiredValues(ctx, cutoff)
		return err
	})
	return ret, err
}
