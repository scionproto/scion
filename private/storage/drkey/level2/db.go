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

package level2

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
	QueriesTotal func(op, result string) metrics.Counter
}

func (m *Metrics) Observe(
	ctx context.Context,
	op string,
	action func(context.Context) error,
) {

	if m == nil {
		_ = action(ctx)
		return
	}

	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("drkeyLevel2DB.%s", op))
	defer span.Finish()

	err := action(ctx)
	label := dblib.ErrToMetricLabel(err)
	tracing.Error(span, err)
	tracing.ResultLabel(span, label)

	if m.QueriesTotal != nil {
		metrics.CounterInc(m.QueriesTotal(op, label))
	}
}

type Database struct {
	Backend drkey.Level2DB
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

func (db *Database) GetASHostKey(
	ctx context.Context,
	meta drkey.ASHostMeta) (drkey.ASHostKey, error) {
	var ret drkey.ASHostKey
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpGetKey,
		func(ctx context.Context) error {
			ret, err = db.Backend.GetASHostKey(ctx, meta)
			return err
		},
	)
	return ret, err
}
func (db *Database) GetHostASKey(
	ctx context.Context,
	meta drkey.HostASMeta) (drkey.HostASKey, error) {
	var ret drkey.HostASKey
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpGetKey,
		func(ctx context.Context) error {
			ret, err = db.Backend.GetHostASKey(ctx, meta)
			return err
		},
	)
	return ret, err
}

func (db *Database) GetHostHostKey(
	ctx context.Context,
	meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	var ret drkey.HostHostKey
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpGetKey,
		func(ctx context.Context) error {
			ret, err = db.Backend.GetHostHostKey(ctx, meta)
			return err
		},
	)
	return ret, err
}

func (db *Database) InsertASHostKey(ctx context.Context, key drkey.ASHostKey) error {
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpInsertKey,
		func(ctx context.Context) error {
			err = db.Backend.InsertASHostKey(ctx, key)
			return err
		},
	)
	return err
}

func (db *Database) InsertHostASKey(ctx context.Context, key drkey.HostASKey) error {
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpInsertKey,
		func(ctx context.Context) error {
			err = db.Backend.InsertHostASKey(ctx, key)
			return err
		},
	)
	return err
}

func (db *Database) InsertHostHostKey(ctx context.Context, key drkey.HostHostKey) error {
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpInsertKey, func(ctx context.Context) error {
			err = db.Backend.InsertHostHostKey(ctx, key)
			return err
		})
	return err
}

func (db *Database) DeleteExpiredASHostKeys(
	ctx context.Context,
	cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpDeleteExpiredKeys,
		func(ctx context.Context) error {
			ret, err = db.Backend.DeleteExpiredASHostKeys(ctx, cutoff)
			return err
		},
	)
	return ret, err
}

func (db *Database) DeleteExpiredHostASKeys(
	ctx context.Context,
	cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpDeleteExpiredKeys,
		func(ctx context.Context) error {
			ret, err = db.Backend.DeleteExpiredHostASKeys(ctx, cutoff)
			return err
		},
	)
	return ret, err
}

func (db *Database) DeleteExpiredHostHostKeys(
	ctx context.Context,
	cutoff time.Time) (int, error) {
	var ret int
	var err error
	db.Metrics.Observe(
		ctx,
		st_drkey.PromOpDeleteExpiredKeys,
		func(ctx context.Context) error {
			ret, err = db.Backend.DeleteExpiredHostHostKeys(ctx, cutoff)
			return err
		},
	)
	return ret, err
}
