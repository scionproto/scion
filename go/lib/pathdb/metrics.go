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

	promOpLabel = "op"
	promDBName  = "db"
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
)

func init() {
	// Cardinality: X (dbName) * 7 (len(allOps))
	queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
		"Total queries to the database.", []string{promDBName, promOpLabel})
	// Cardinality: X (dbNmae) * 7 (len(allOps)) * 3 (len(allResults))
	resultsTotal = prom.NewCounterVec(promNamespace, "", "results_total",
		"The results of the pathdb ops.", []string{promDBName, prom.LabelResult, promOpLabel})
}

type dbCounters struct {
	opCounters     map[promOp]prometheus.Counter
	resultCounters map[promOp]map[string]prometheus.Counter
}

// WithMetrics wraps the given PathDB into one that also exports metrics.
// dbName will be added as a label to all metrics, so that multiple path DBs can be differentiated.
func WithMetrics(dbName string, pathDB PathDB) PathDB {
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
			promDBName:  dbName,
			promOpLabel: string(op),
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
				promDBName:       dbName,
				promOpLabel:      string(op),
				prom.LabelResult: res,
			})
		}
	}
	return resultCounters
}

var _ (PathDB) = (*metricsPathDB)(nil)

// metricsPathDB is a PathDB wrapper that exports the counts of operations as prometheus metrics.
type metricsPathDB struct {
	pathDB  PathDB
	metrics *dbCounters
}

func (db *metricsPathDB) Insert(ctx context.Context, meta *seg.Meta) (int, error) {
	db.incOp(promOpInsert)
	cnt, err := db.pathDB.Insert(ctx, meta)
	db.incErr(promOpInsert, err)
	return cnt, err
}

func (db *metricsPathDB) InsertWithHPCfgIDs(ctx context.Context,
	meta *seg.Meta, hpCfgIds []*query.HPCfgID) (int, error) {

	db.incOp(promOpInsertHpCfg)
	cnt, err := db.pathDB.InsertWithHPCfgIDs(ctx, meta, hpCfgIds)
	db.incErr(promOpInsertHpCfg, err)
	return cnt, err
}

func (db *metricsPathDB) Delete(ctx context.Context, params *query.Params) (int, error) {
	db.incOp(promOpDelete)
	cnt, err := db.pathDB.Delete(ctx, params)
	db.incErr(promOpDelete, err)
	return cnt, err
}

func (db *metricsPathDB) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	db.incOp(promOpDeleteExpired)
	cnt, err := db.pathDB.DeleteExpired(ctx, now)
	db.incErr(promOpDeleteExpired, err)
	return cnt, err
}

func (db *metricsPathDB) Get(ctx context.Context,
	params *query.Params) ([]*query.Result, error) {

	db.incOp(promOpGet)
	res, err := db.pathDB.Get(ctx, params)
	db.incErr(promOpGet, err)
	return res, err
}

func (db *metricsPathDB) InsertNextQuery(ctx context.Context,
	dst addr.IA, nextQuery time.Time) (bool, error) {

	db.incOp(promOpInsertNextQuery)
	ok, err := db.pathDB.InsertNextQuery(ctx, dst, nextQuery)
	db.incErr(promOpInsertNextQuery, err)
	return ok, err
}

func (db *metricsPathDB) GetNextQuery(ctx context.Context, dst addr.IA) (*time.Time, error) {
	db.incOp(promOpGetNextQuery)
	t, err := db.pathDB.GetNextQuery(ctx, dst)
	db.incErr(promOpGetNextQuery, err)
	return t, err
}

func (db *metricsPathDB) incOp(op promOp) {
	db.metrics.opCounters[op].Inc()
}

func (db *metricsPathDB) incErr(op promOp, err error) {
	// TODO(lukedirtwalker): categorize error better.
	switch {
	case err == nil:
		db.metrics.resultCounters[op][prom.ResultOk].Inc()
	case common.IsTimeoutErr(err):
		db.metrics.resultCounters[op][prom.ErrTimeout].Inc()
	default:
		db.metrics.resultCounters[op][prom.ErrNotClassified].Inc()
	}
}
