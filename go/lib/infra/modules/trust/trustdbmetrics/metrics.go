// Copyright 2020 Anapaya Systems
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

package trustdbmetrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	dblib "github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/decoded"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/tracing"
)

type observer struct {
	driver string
}

func (o observer) Observe(ctx context.Context, op string, action func(ctx context.Context) error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("trustdb.%s", string(op)))
	defer span.Finish()
	err := action(ctx)

	label := errToLabel(err)
	ext.Error.Set(span, err != nil)
	tracing.ResultLabel(span, label)

	l := metrics.QueryLabels{
		Driver:    o.driver,
		Operation: op,
		Result:    label,
	}
	metrics.DB.Queries(l).Inc()
}

var _ (trust.DB) = (*db)(nil)

type db struct {
	*executor
	backend interface {
		io.Closer
		dblib.LimitSetter
		BeginTransaction(ctx context.Context, opts *sql.TxOptions) (trust.Transaction, error)
	}
}

// WithMetrics wraps the given TrustDB into one that also exports metrics.
func WithMetrics(driver string, trustDB trust.DB) trust.DB {
	rwWrapper := &executor{
		rw: trustDB,
		metrics: observer{
			driver: driver,
		},
	}
	return &db{
		executor: rwWrapper,
		backend:  trustDB,
	}
}

func (d *db) BeginTransaction(ctx context.Context, opts *sql.TxOptions) (trust.Transaction, error) {
	var t trust.Transaction
	var err error
	d.executor.metrics.Observe(ctx, metrics.BeginTx, func(ctx context.Context) error {
		t, err = d.backend.BeginTransaction(ctx, opts)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &tx{
		backend: t,
		ctx:     ctx,
		executor: &executor{
			rw:      t,
			metrics: d.executor.metrics,
		},
	}, err
}

func (d *db) SetMaxOpenConns(maxOpenConns int) {
	d.backend.SetMaxOpenConns(maxOpenConns)
}

func (d *db) SetMaxIdleConns(maxIdleConns int) {
	d.backend.SetMaxIdleConns(maxIdleConns)
}

func (d *db) Close() error {
	return d.backend.Close()
}

var _ (trust.Transaction) = (*tx)(nil)

type tx struct {
	*executor
	// tx is only used for Commit and Rollback.
	backend interface {
		Commit() error
		Rollback() error
	}
	ctx context.Context
}

func (t *tx) Commit() error {
	var err error
	t.metrics.Observe(t.ctx, metrics.CommitTx, func(_ context.Context) error {
		err = t.backend.Commit()
		return err
	})
	return err
}

func (t *tx) Rollback() error {
	var err error
	t.metrics.Observe(t.ctx, metrics.RollbackTx, func(_ context.Context) error {
		err = t.backend.Rollback()
		if err == sql.ErrTxDone {
			return nil
		}
		return err
	})
	return err
}

type executor struct {
	rw      trust.ReadWrite
	metrics observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (e *executor) TRCExists(ctx context.Context, d decoded.TRC) (bool, error) {
	var exists bool
	var err error
	e.metrics.Observe(ctx, metrics.TRCExists, func(ctx context.Context) error {
		exists, err = e.rw.TRCExists(ctx, d)
		return err
	})
	return exists, err
}

func (e *executor) GetTRC(ctx context.Context, id trust.TRCID) (*trc.TRC, error) {
	var t *trc.TRC
	var err error
	e.metrics.Observe(ctx, metrics.GetTRC, func(ctx context.Context) error {
		t, err = e.rw.GetTRC(ctx, id)
		return err
	})
	return t, err
}

func (e *executor) GetRawTRC(ctx context.Context, id trust.TRCID) ([]byte, error) {
	var raw []byte
	var err error
	e.metrics.Observe(ctx, metrics.GetRawTRC, func(ctx context.Context) error {
		raw, err = e.rw.GetRawTRC(ctx, id)
		return err
	})
	return raw, err

}

func (e *executor) GetTRCInfo(ctx context.Context, id trust.TRCID) (trust.TRCInfo, error) {
	var info trust.TRCInfo
	var err error
	e.metrics.Observe(ctx, metrics.GetTRCInfo, func(ctx context.Context) error {
		info, err = e.rw.GetTRCInfo(ctx, id)
		return err
	})
	return info, err
}

func (e *executor) GetIssuingGrantKeyInfo(ctx context.Context, ia addr.IA,
	version scrypto.Version) (trust.KeyInfo, error) {

	var info trust.KeyInfo
	var err error
	e.metrics.Observe(ctx, metrics.GetIssuingGrantKeyInfo, func(ctx context.Context) error {
		info, err = e.rw.GetIssuingGrantKeyInfo(ctx, ia, version)
		return err
	})
	return info, err
}

func (e *executor) InsertTRC(ctx context.Context, d decoded.TRC) (bool, error) {
	var inserted bool
	var err error
	e.metrics.Observe(ctx, metrics.InsertTRC, func(ctx context.Context) error {
		inserted, err = e.rw.InsertTRC(ctx, d)
		return err
	})
	return inserted, err
}

func (e *executor) GetRawChain(ctx context.Context, id trust.ChainID) ([]byte, error) {
	var raw []byte
	var err error
	e.metrics.Observe(ctx, metrics.GetRawChain, func(ctx context.Context) error {
		raw, err = e.rw.GetRawChain(ctx, id)
		return err
	})
	return raw, err
}

func (e *executor) ChainExists(ctx context.Context, d decoded.Chain) (bool, error) {
	var exists bool
	var err error
	e.metrics.Observe(ctx, metrics.ChainExists, func(ctx context.Context) error {
		exists, err = e.rw.ChainExists(ctx, d)
		return err
	})
	return exists, err
}

func (e *executor) InsertChain(ctx context.Context, d decoded.Chain) (bool, bool, error) {
	var chain, issuer bool
	var err error
	e.metrics.Observe(ctx, metrics.InsertChain, func(ctx context.Context) error {
		chain, issuer, err = e.rw.InsertChain(ctx, d)
		return err
	})
	return chain, issuer, err
}

func errToLabel(err error) string {
	switch {
	case errors.Is(err, trust.ErrNotFound):
		return metrics.ErrNotFound
	case errors.Is(err, trust.ErrContentMismatch):
		return metrics.ErrMismatch
	default:
		return dblib.ErrToMetricLabel(err)
	}
}
