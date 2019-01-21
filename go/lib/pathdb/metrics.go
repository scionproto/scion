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
	errorsTotal  *prometheus.CounterVec
)

func init() {
	queriesTotal = prom.NewCounterVec(promNamespace, "", "queries_total",
		"Total queries to the database.", []string{promDBName, promOpLabel})
	errorsTotal = prom.NewCounterVec(promNamespace, "", "errors_total",
		"Amount of pathdb errors.", []string{promDBName, prom.LabelErr})
}

type dbCounters struct {
	readQueriesTotal  prometheus.Counter
	writeQueriesTotal prometheus.Counter
	errAnyTotal       prometheus.Counter
	errTimeoutTotal   prometheus.Counter
}

// WithMetrics wraps the given PathDB into one that also exports metrics.
// dbName will be added as a label to all metrics, so that multiple path DBs can be differentiatetd.
func WithMetrics(dbName string, pathDB PathDB) PathDB {
	return &metricsPathDB{
		pathDB: pathDB,
		metrics: &dbCounters{
			readQueriesTotal: queriesTotal.With(prometheus.Labels{
				promDBName:  dbName,
				promOpLabel: "read",
			}),
			writeQueriesTotal: queriesTotal.With(prometheus.Labels{
				promDBName:  dbName,
				promOpLabel: "write",
			}),
			errAnyTotal: errorsTotal.With(prometheus.Labels{
				promDBName:    dbName,
				prom.LabelErr: prom.ErrNotClassified,
			}),
			errTimeoutTotal: errorsTotal.With(prometheus.Labels{
				promDBName:    dbName,
				prom.LabelErr: prom.ErrTimeout,
			}),
		},
	}
}

var _ (PathDB) = (*metricsPathDB)(nil)

// metricsPathDB is a PathDB wrapper that exports the counts of operations as prometheus metrics.
type metricsPathDB struct {
	pathDB  PathDB
	metrics *dbCounters
}

func (db *metricsPathDB) Insert(ctx context.Context, meta *seg.Meta) (int, error) {
	db.incWrite()
	cnt, err := db.pathDB.Insert(ctx, meta)
	db.incErr(err)
	return cnt, err
}

func (db *metricsPathDB) InsertWithHPCfgIDs(ctx context.Context,
	meta *seg.Meta, hpCfgIds []*query.HPCfgID) (int, error) {

	db.incWrite()
	cnt, err := db.pathDB.InsertWithHPCfgIDs(ctx, meta, hpCfgIds)
	db.incErr(err)
	return cnt, err
}

func (db *metricsPathDB) Delete(ctx context.Context, params *query.Params) (int, error) {
	db.incWrite()
	cnt, err := db.pathDB.Delete(ctx, params)
	db.incErr(err)
	return cnt, err
}

func (db *metricsPathDB) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	db.incWrite()
	cnt, err := db.pathDB.DeleteExpired(ctx, now)
	db.incErr(err)
	return cnt, err
}

func (db *metricsPathDB) Get(ctx context.Context,
	params *query.Params) ([]*query.Result, error) {

	db.incRead()
	res, err := db.pathDB.Get(ctx, params)
	db.incErr(err)
	return res, err
}

func (db *metricsPathDB) InsertNextQuery(ctx context.Context,
	dst addr.IA, nextQuery time.Time) (bool, error) {

	db.incWrite()
	ok, err := db.pathDB.InsertNextQuery(ctx, dst, nextQuery)
	db.incErr(err)
	return ok, err
}

func (db *metricsPathDB) GetNextQuery(ctx context.Context, dst addr.IA) (*time.Time, error) {
	db.incRead()
	t, err := db.pathDB.GetNextQuery(ctx, dst)
	db.incErr(err)
	return t, err
}

func (db *metricsPathDB) incRead() {
	db.metrics.readQueriesTotal.Inc()
}

func (db *metricsPathDB) incWrite() {
	db.metrics.writeQueriesTotal.Inc()
}

func (db *metricsPathDB) incErr(err error) {
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
