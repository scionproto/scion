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

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/private/storage"
	storagebeacon "github.com/scionproto/scion/private/storage/beacon"
	dblib "github.com/scionproto/scion/private/storage/db"
	"github.com/scionproto/scion/private/tracing"
)

type Config struct {
	Driver       string
	QueriesTotal metrics.Counter
}

// WrapDB wraps the given beacon database into one that also exports metrics.
func WrapDB(beaconDB storage.BeaconDB, cfg Config) storage.BeaconDB {
	return &db{
		db:      beaconDB,
		metrics: Observer{Cfg: cfg},
	}
}

type Observer struct {
	Cfg Config
}

type Observable func(context.Context) (label string, err error)

func (o Observer) Observe(ctx context.Context, op string, action Observable) {
	span, ctx := opentracing.StartSpanFromContext(ctx, fmt.Sprintf("beacondb.%s", op))
	defer span.Finish()
	label, err := action(ctx)

	tracing.ResultLabel(span, label)
	tracing.Error(span, err)

	labels := queryLabels{
		Driver:    o.Cfg.Driver,
		Operation: op,
		Result:    label,
	}
	metrics.CounterInc(metrics.CounterWith(o.Cfg.QueriesTotal, labels.Expand()...))
}

type db struct {
	db      storage.BeaconDB
	metrics Observer
}

// below here is very boilerplaty code that implements all DB ops and calls the Observe function.

func (d *db) CandidateBeacons(
	ctx context.Context,
	setSize int,
	usage beacon.Usage,
	src addr.IA,
) ([]beacon.Beacon, error) {

	var ret []beacon.Beacon
	var err error
	d.metrics.Observe(ctx, "candidate_beacons", func(ctx context.Context) (string, error) {
		ret, err = d.db.CandidateBeacons(ctx, setSize, usage, src)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (d *db) BeaconSources(ctx context.Context) ([]addr.IA, error) {
	var ret []addr.IA
	var err error
	d.metrics.Observe(ctx, "beacon_srcs", func(ctx context.Context) (string, error) {
		ret, err = d.db.BeaconSources(ctx)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (d *db) InsertBeacon(
	ctx context.Context,
	b beacon.Beacon,
	usage beacon.Usage,
) (beacon.InsertStats, error) {

	var ret beacon.InsertStats
	var err error
	d.metrics.Observe(ctx, "insert_beacon", func(ctx context.Context) (string, error) {
		ret, err = d.db.InsertBeacon(ctx, b, usage)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (d *db) GetBeacons(
	ctx context.Context,
	q *storagebeacon.QueryParams,
) ([]storagebeacon.Beacon, error) {

	var ret []storagebeacon.Beacon
	var err error
	d.metrics.Observe(ctx, "get_beacons", func(ctx context.Context) (string, error) {
		ret, err = d.db.GetBeacons(ctx, q)
		return dblib.ErrToMetricLabel(err), err
	})
	return ret, err
}

func (d *db) DeleteBeacon(ctx context.Context, partialID string) error {
	var err error
	d.metrics.Observe(ctx, "delete_beacon", func(ctx context.Context) (string, error) {
		err = d.db.DeleteBeacon(ctx, partialID)
		return dblib.ErrToMetricLabel(err), err
	})
	return err
}

func (d *db) Close() error {
	return d.db.Close()
}

type queryLabels struct {
	Driver    string
	Operation string
	Result    string
}

func (l queryLabels) Expand() []string {
	return []string{"driver", l.Driver, "operation", l.Operation, prom.LabelResult, l.Result}
}
