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

package secret

import (
	"context"
	"fmt"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/metrics"
	dblib "github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/tracing"
)

const (
	promOpGetSV           = "get_sv"
	promOpInsertSV        = "insert_sv"
	promOpDeleteExpiredSV = "delete_expired_sv"
)

type Metrics struct {
	QueriesSVTotal metrics.Counter
	ResultsSVTotal metrics.Counter
}

func (m *Metrics) Observe(ctx context.Context, op string, action func(context.Context) error) {
	if m == nil {
		_ = action(ctx)
		return
	}

	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeySVDB.%s", op))
	defer span.Finish()

	metrics.CounterInc(metrics.CounterWith(m.QueriesSVTotal, "operation", op))
	err := action(ctx)

	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	metrics.CounterInc(metrics.CounterWith(m.ResultsSVTotal, "operation", op))
}

type Database struct {
	Backend drkey.SecretValueDB
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

func (db *Database) GetValue(ctx context.Context,
	meta drkey.SecretValueMeta, asSecret []byte) (drkey.SecretValue, error) {
	var ret drkey.SecretValue
	var err error
	db.Metrics.Observe(ctx, promOpGetSV, func(ctx context.Context) error {
		ret, err = db.Backend.GetValue(ctx, meta, asSecret)
		return err
	})
	return ret, err
}

func (db *Database) InsertValue(ctx context.Context,
	proto drkey.Protocol, epoch drkey.Epoch) error {
	var err error
	db.Metrics.Observe(ctx, promOpInsertSV, func(ctx context.Context) error {
		err = db.Backend.InsertValue(ctx, proto, epoch)
		return err
	})
	return err
}

func (db *Database) DeleteExpiredValues(ctx context.Context, cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.Metrics.Observe(ctx, promOpDeleteExpiredSV, func(ctx context.Context) error {
		ret, err = db.Backend.DeleteExpiredValues(ctx, cutoff)
		return err
	})

	return ret, err
}
