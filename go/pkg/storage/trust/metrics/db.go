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
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/storage"
	truststorage "github.com/scionproto/scion/go/pkg/storage/trust"
	"github.com/scionproto/scion/go/pkg/trust"
)

const (
	errNotFound = "err_not_found"
)

// Config configures the metrics for the wrapped trust database.
type Config struct {
	Driver       string
	QueriesTotal metrics.Counter
}

// WrapDB wraps the given trust database into one that also exports metrics.
func WrapDB(trustDB storage.TrustDB, cfg Config) storage.TrustDB {
	rwWrapper := &executor{
		db: trustDB,
		metrics: observer{
			cfg: cfg,
		},
	}
	return &db{
		executor: rwWrapper,
	}
}

type observer struct {
	cfg Config
}

type observable func(context.Context) (label string, err error)

func (o observer) Observe(ctx context.Context, op string, action observable) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("trustdb.%s", string(op)))
	defer span.Finish()
	label, err := action(ctx)

	tracing.ResultLabel(span, label)
	tracing.Error(span, err)

	labels := queryLabels{
		Driver:    o.cfg.Driver,
		Operation: op,
		Result:    label,
	}
	metrics.CounterInc(metrics.CounterWith(o.cfg.QueriesTotal, labels.Expand()...))
}

var _ (trust.DB) = (*db)(nil)

type db struct {
	*executor
	backend io.Closer
}

func (db *db) Close() error {
	return db.backend.Close()
}

type executor struct {
	db interface {
		truststorage.TrustAPI
		trust.DB
	}
	metrics observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (e *executor) SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	var trc cppki.SignedTRC
	var err error
	e.metrics.Observe(ctx, "get_signed_trc", func(ctx context.Context) (string, error) {
		trc, err = e.db.SignedTRC(ctx, id)
		label := dblib.ErrToMetricLabel(err)
		if trc.IsZero() && err == nil {
			label = errNotFound
		}
		return label, err
	})
	return trc, err
}

func (e *executor) SignedTRCs(ctx context.Context,
	query truststorage.TRCsQuery) (cppki.SignedTRCs, error) {
	var trcs cppki.SignedTRCs
	var err error
	e.metrics.Observe(ctx, "get_signed_trcs", func(ctx context.Context) (string, error) {
		trcs, err = e.db.SignedTRCs(ctx, query)
		label := dblib.ErrToMetricLabel(err)
		if len(trcs) == 0 && err == nil {
			label = errNotFound
		}
		return label, err
	})
	return trcs, err
}

func (e *executor) InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error) {
	var inserted bool
	var err error
	e.metrics.Observe(ctx, "insert_trc", func(ctx context.Context) (string, error) {
		inserted, err = e.db.InsertTRC(ctx, trc)
		return dblib.ErrToMetricLabel(err), err
	})
	return inserted, err
}

func (e *executor) Chains(ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {
	var chains [][]*x509.Certificate
	var err error
	e.metrics.Observe(ctx, "get_chains", func(ctx context.Context) (string, error) {
		chains, err = e.db.Chains(ctx, q)
		label := dblib.ErrToMetricLabel(err)
		if len(chains) == 0 && err == nil {
			label = errNotFound
		}
		return label, err
	})
	return chains, err
}

func (e *executor) Chain(ctx context.Context, id []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	var err error
	e.metrics.Observe(ctx, "get_chain", func(ctx context.Context) (string, error) {
		chain, err = e.db.Chain(ctx, id)
		label := dblib.ErrToMetricLabel(err)
		if len(chain) == 0 && err == nil {
			label = errNotFound
		}
		return label, err
	})
	return chain, err
}

func (e *executor) InsertChain(ctx context.Context, chain []*x509.Certificate) (bool, error) {
	var inserted bool
	var err error
	e.metrics.Observe(ctx, "insert_chain", func(ctx context.Context) (string, error) {
		inserted, err = e.db.InsertChain(ctx, chain)
		return dblib.ErrToMetricLabel(err), err
	})
	return inserted, err
}

type queryLabels struct {
	Driver    string
	Operation string
	Result    string
}

func (l queryLabels) Expand() []string {
	return []string{"driver", l.Driver, "operation", l.Operation, prom.LabelResult, l.Result}
}
