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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/prom"
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
	promOpInsertNextQuery promOp = "insert_next_query"
	promOpGetNextQuery    promOp = "get_next_query"
)

var (
	queriesTotal *prometheus.CounterVec
	resultsTotal *prometheus.CounterVec

	allOps = []promOp{
		promOpInsert,
		promOpInsertHpCfg,
		promOpDelete,
		promOpDeleteExpired,
		promOpGet,
		promOpInsertNextQuery,
		promOpGetNextQuery,
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
		// Cardinality: X (dbName) * 7 (len(allOps))
		queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
			"Total queries to the database.", []string{promDBName, prom.LabelOperation})
		// Cardinality: X (dbNmae) * 7 (len(allOps)) * 3 (len(allResults))
		resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
			"The results of the pathdb ops.",
			[]string{promDBName, prom.LabelResult, prom.LabelOperation})
	})
}

// WithMetrics wraps the given PathDB into one that also exports metrics.
// dbName will be added as a label to all metrics, so that multiple path DBs can be differentiated.
func WithMetrics(dbName string, pathDB PathDB) PathDB {
	initMetrics()
	return &metricsPathDB{
		pathDB: pathDB,
		metrics: &dbCounters{
			opCounters:     opCounters(dbName),
			resultCounters: resultCounters(dbName),
		},
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

type dbCounters struct {
	opCounters     map[promOp]prometheus.Counter
	resultCounters map[promOp]map[string]prometheus.Counter
}

func (c *dbCounters) incOp(op promOp) {
	c.opCounters[op].Inc()
}

func (c *dbCounters) incResult(op promOp, err error) {
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

var _ (PathDB) = (*metricsPathDB)(nil)

// metricsPathDB is a PathDB wrapper that exports the counts of operations as prometheus metrics.
type metricsPathDB struct {
	pathDB  PathDB
	metrics *dbCounters
}

func (db *metricsPathDB) Insert(ctx context.Context, meta *seg.Meta) (int, error) {
	db.metrics.incOp(promOpInsert)
	cnt, err := db.pathDB.Insert(ctx, meta)
	db.metrics.incResult(promOpInsert, err)
	return cnt, err
}

func (db *metricsPathDB) InsertWithHPCfgIDs(ctx context.Context,
	meta *seg.Meta, hpCfgIds []*query.HPCfgID) (int, error) {

	db.metrics.incOp(promOpInsertHpCfg)
	cnt, err := db.pathDB.InsertWithHPCfgIDs(ctx, meta, hpCfgIds)
	db.metrics.incResult(promOpInsertHpCfg, err)
	return cnt, err
}

func (db *metricsPathDB) Delete(ctx context.Context, params *query.Params) (int, error) {
	db.metrics.incOp(promOpDelete)
	cnt, err := db.pathDB.Delete(ctx, params)
	db.metrics.incResult(promOpDelete, err)
	return cnt, err
}

func (db *metricsPathDB) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	db.metrics.incOp(promOpDeleteExpired)
	cnt, err := db.pathDB.DeleteExpired(ctx, now)
	db.metrics.incResult(promOpDeleteExpired, err)
	return cnt, err
}

func (db *metricsPathDB) Get(ctx context.Context,
	params *query.Params) ([]*query.Result, error) {

	db.metrics.incOp(promOpGet)
	res, err := db.pathDB.Get(ctx, params)
	db.metrics.incResult(promOpGet, err)
	return res, err
}

func (db *metricsPathDB) InsertNextQuery(ctx context.Context,
	dst addr.IA, nextQuery time.Time) (bool, error) {

	db.metrics.incOp(promOpInsertNextQuery)
	ok, err := db.pathDB.InsertNextQuery(ctx, dst, nextQuery)
	db.metrics.incResult(promOpInsertNextQuery, err)
	return ok, err
}

func (db *metricsPathDB) GetNextQuery(ctx context.Context, dst addr.IA) (*time.Time, error) {
	db.metrics.incOp(promOpGetNextQuery)
	t, err := db.pathDB.GetNextQuery(ctx, dst)
	db.metrics.incResult(promOpGetNextQuery, err)
	return t, err
}
