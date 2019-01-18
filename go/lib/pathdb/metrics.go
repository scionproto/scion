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
	promSubsyst = "pathdb"

	promQuery  = "query"
	promDBName = "db"
	promError  = "err"
)

var (
	queriesTotal *prometheus.CounterVec
	errorsTotal  *prometheus.CounterVec
)

type dbCounters struct {
	readQueriesTotal  prometheus.Counter
	writeQueriesTotal prometheus.Counter
	errorsTotal       *prometheus.CounterVec
}

// InitMetrics prepares the usage of metrics in the pathdb module.
func InitMetrics(namespace string) {
	queriesTotal = prom.NewCounterVec(namespace, promSubsyst, "queries_total",
		"Total queries to the database.", []string{promDBName, promQuery})
	errorsTotal = prom.NewCounterVec(namespace, promSubsyst, "errors_total",
		"Amount of pathdb errors.", []string{promDBName, promError})
}

// WithMetrics wraps the given PathDB into one that also exports metrics.
// InitMetrics must have been called previously, otherwise this method panics.
func WithMetrics(dbName string, pathDB PathDB) PathDB {
	if queriesTotal == nil || errorsTotal == nil {
		panic("Must call InitMetrics first!")
	}
	return &metricsPathDB{
		pathDB: pathDB,
		metrics: &dbCounters{
			readQueriesTotal: queriesTotal.With(prometheus.Labels{
				promDBName: dbName,
				promQuery:  "read",
			}),
			writeQueriesTotal: queriesTotal.With(prometheus.Labels{
				promDBName: dbName,
				promQuery:  "write",
			}),
			errorsTotal: errorsTotal.MustCurryWith(prometheus.Labels{
				promDBName: dbName,
			}),
		},
	}
}

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
	db.metrics.errorsTotal.With(prometheus.Labels{promError: errDesc(err)}).Inc()
}

func errDesc(err error) string {
	// TODO(lukedirtwalker): categorize error better.
	switch {
	case common.IsTimeoutErr(err):
		return "err_timeout"
	default:
		return "err_any"
	}
}
