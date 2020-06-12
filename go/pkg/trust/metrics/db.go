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

package metrics

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/opentracing/opentracing-go"

	dblib "github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/pkg/trust/internal/metrics"
)

type observer struct {
	driver string
}

type observable func(context.Context) (label string, err error)

func (o observer) Observe(ctx context.Context, op string, action observable) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("trustdb.%s", string(op)))
	defer span.Finish()
	label, err := action(ctx)

	tracing.ResultLabel(span, label)
	tracing.Error(span, err)

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
	}
}

// WrapDB wraps the given trust database into one that also exports metrics.
func WrapDB(driver string, trustDB trust.DB) trust.DB {
	rwWrapper := &executor{
		db: trustDB,
		metrics: observer{
			driver: driver,
		},
	}
	return &db{
		executor: rwWrapper,
		backend:  trustDB,
	}
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

type executor struct {
	db      trust.DB
	metrics observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (e *executor) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	var trc cppki.SignedTRC
	var err error
	e.metrics.Observe(ctx, metrics.SignedTRC, func(ctx context.Context) (string, error) {
		trc, err = e.db.SignedTRC(ctx, id)
		label := dblib.ErrToMetricLabel(err)
		if trc.IsZero() && err == nil {
			label = metrics.ErrNotFound
		}
		return label, err
	})
	return trc, err
}

func (e *executor) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	var inserted bool
	var err error
	e.metrics.Observe(ctx, metrics.InsertTRC, func(ctx context.Context) (string, error) {
		inserted, err = e.db.InsertTRC(ctx, trc)
		return dblib.ErrToMetricLabel(err), err
	})
	return inserted, err
}

func (e *executor) Chains(ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {
	var chains [][]*x509.Certificate
	var err error
	e.metrics.Observe(ctx, metrics.Chains, func(ctx context.Context) (string, error) {
		chains, err = e.db.Chains(ctx, q)
		label := dblib.ErrToMetricLabel(err)
		if len(chains) == 0 && err == nil {
			label = metrics.ErrNotFound
		}
		return label, err
	})
	return chains, err
}
func (e *executor) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	var inserted bool
	var err error
	e.metrics.Observe(ctx, metrics.InsertChain, func(ctx context.Context) (string, error) {
		inserted, err = e.db.InsertChain(ctx, chain)
		return dblib.ErrToMetricLabel(err), err
	})
	return inserted, err
}
