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

package metrics

import (
	"context"
	"fmt"
	"io"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/addr"
	dblib "github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/tracing"
	"github.com/scionproto/scion/go/pkg/storage"
)

type Config struct {
	Driver       string
	QueriesTotal metrics.Counter
}

// WrapDB wraps the given beacon database into one that also exports metrics.
func WrapDB(beaconDB storage.BeaconDB, cfg Config) storage.BeaconDB {
	wrapper := &executor{
		db: beaconDB,
		metrics: observer{
			cfg: cfg,
		},
	}
	return &db{
		executor: wrapper,
		backend:  beaconDB,
	}
}

type observer struct {
	cfg Config
}

type observable func(context.Context) (label string, err error)

func (o observer) Observe(ctx context.Context, op string, action observable) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("beacondb.%s", op))
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

type db struct {
	*executor
	backend io.Closer
}

func (db *db) Close() error {
	return db.backend.Close()
}

type executor struct {
	db interface {
		beacon.DB
	}
	metrics observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (e *executor) CandidateBeacons(
	ctx context.Context,
	setSize int,
	usage beacon.Usage,
	src addr.IA,
) ([]beacon.BeaconOrErr, error) {

	var ret []beacon.BeaconOrErr
	var err error
	e.metrics.Observe(ctx, "candidate_beacons", func(ctx context.Context) (string, error) {
		ret, err = e.db.CandidateBeacons(ctx, setSize, usage, src)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (e *executor) BeaconSources(ctx context.Context) ([]addr.IA, error) {
	var ret []addr.IA
	var err error
	e.metrics.Observe(ctx, "beacon_srcs", func(ctx context.Context) (string, error) {
		ret, err = e.db.BeaconSources(ctx)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (e *executor) InsertBeacon(
	ctx context.Context,
	b beacon.Beacon,
	usage beacon.Usage,
) (beacon.InsertStats, error) {

	var ret beacon.InsertStats
	var err error
	e.metrics.Observe(ctx, "insert_beacon", func(ctx context.Context) (string, error) {
		ret, err = e.db.InsertBeacon(ctx, b, usage)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

type queryLabels struct {
	Driver    string
	Operation string
	Result    string
}

func (l queryLabels) Expand() []string {
	return []string{"driver", l.Driver, "operation", l.Operation, prom.LabelResult, l.Result}
}
