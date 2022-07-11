// Copyright 2022 ETH Zurich
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

package level1

import (
	"context"
	"fmt"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/metrics"
	dblib "github.com/scionproto/scion/private/storage/db"
	st_drkey "github.com/scionproto/scion/private/storage/drkey"
	"github.com/scionproto/scion/private/tracing"
)

type Metrics struct {
	QueriesTotal metrics.Counter
	ResultsTotal metrics.Counter
}

func (m *Metrics) Observe(ctx context.Context, op string, action func(context.Context) error) {
	if m == nil {
		_ = action(ctx)
		return
	}

	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeyLevel1DB.%s", op))
	defer span.Finish()

	metrics.CounterInc(metrics.CounterWith(m.QueriesTotal, "operation", op))
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	metrics.CounterInc(metrics.CounterWith(m.ResultsTotal, "operation", op))
}

type Database struct {
	Backend drkey.Level1DB
	Metrics *Metrics
}

func (db *Database) SetMaxOpenConns(maxOpenConns int) {
	db.Backend.SetMaxOpenConns(maxOpenConns)
}

func (db *Database) SetMaxIdleConns(maxIdleConns int) {
	db.Backend.SetMaxIdleConns(maxIdleConns)
}

func (db *Database) Close() error {
	return db.Backend.Close()
}

func (db *Database) GetLevel1Key(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {

	var ret drkey.Level1Key
	var err error
	db.Metrics.Observe(ctx, st_drkey.PromOpGetKey, func(ctx context.Context) error {
		ret, err = db.Backend.GetLevel1Key(ctx, meta)
		return err
	})
	return ret, err
}

func (db *Database) InsertLevel1Key(ctx context.Context, key drkey.Level1Key) error {
	var err error
	db.Metrics.Observe(ctx, st_drkey.PromOpInsertKey, func(ctx context.Context) error {
		err = db.Backend.InsertLevel1Key(ctx, key)
		return err
	})
	return err
}

func (db *Database) DeleteExpiredLevel1Keys(ctx context.Context,
	cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.Metrics.Observe(ctx, st_drkey.PromOpDeleteExpiredKeys, func(ctx context.Context) error {
		ret, err = db.Backend.DeleteExpiredLevel1Keys(ctx, cutoff)
		return err
	})
	return ret, err
}
