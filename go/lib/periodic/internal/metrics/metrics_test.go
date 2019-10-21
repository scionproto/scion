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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/prom/promtest"
)

func TestLabels(t *testing.T) {
	promtest.CheckLabelsStruct(t, EventLabels{})
}

func TestNewMetric(t *testing.T) {
	t.Run("Returns valid exporter", func(t *testing.T) {
		rnd := fmt.Sprintf("%v", time.Now().Unix())
		n := "randomSnakeName" + rnd
		w := func() {
			x := NewMetric(n)
			x.Period(time.Second)
			x.Runtime(time.Second)
			x.Event("dummy")
			x.StartTimestamp(time.Now())
		}
		require.NotPanics(t, w)
	})

	t.Run("Same name does not panic", func(t *testing.T) {
		n := "randomOtherName"
		NewMetric(n)
		w := func() {
			NewMetric(n)
		}
		require.NotPanics(t, w)
	})

	t.Run("Invalid name does not panic", func(t *testing.T) {
		n := "random.NameWithDot"
		w := func() {
			NewMetric(n)
		}
		require.NotPanics(t, w)
	})

	t.Run("Never panics", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			go NewMetric("x")
		}
	})
}

func TestContent(t *testing.T) {
	t.Run("Runtime", func(t *testing.T) {
		rnd := fmt.Sprintf("%v", time.Now().Nanosecond())
		n, sn := "randomName"+rnd, "random_name_"+rnd
		v := newExporter(n)

		want := fmt.Sprintf(`
# HELP %s_periodic_runtime_duration_seconds_total Total time spend on every periodic run.
# TYPE %s_periodic_runtime_duration_seconds_total counter
%s_periodic_runtime_duration_seconds_total 1
	`, sn, sn, sn)
		v.Runtime(1 * time.Second)
		err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("StartTimestamp", func(t *testing.T) {
		rnd := fmt.Sprintf("%v", time.Now().Nanosecond())
		n, sn := "randomName"+rnd, "random_name_"+rnd
		v := newExporter(n)

		want := fmt.Sprintf(`
# HELP %s_periodic_runtime_timestamp_seconds The unix timestamp when the periodic run started.
# TYPE %s_periodic_runtime_timestamp_seconds gauge
%s_periodic_runtime_timestamp_seconds 1.570633374e+09
	`, sn, sn, sn)
		ts := time.Unix(1570633374, 0)
		v.StartTimestamp(ts)
		err := testutil.CollectAndCompare(v.timestamp, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Event", func(t *testing.T) {
		rnd := fmt.Sprintf("%v", time.Now().Nanosecond())
		n, sn := "randomName"+rnd, "random_name_"+rnd
		v := newExporter(n)

		want := fmt.Sprintf(`
# HELP %s_periodic_event_total Total number of events.
# TYPE %s_periodic_event_total counter
%s_periodic_event_total{event_type="kill"} 1
	`, sn, sn, sn)
		v.Event(EventKill)
		err := testutil.CollectAndCompare(v.events, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Period", func(t *testing.T) {
		rnd := fmt.Sprintf("%v", time.Now().Nanosecond())
		n, sn := "randomName"+rnd, "random_name_"+rnd
		v := newExporter(n)

		want := fmt.Sprintf(`
# HELP %s_periodic_period_duration_seconds The period of this job.
# TYPE %s_periodic_period_duration_seconds gauge
%s_periodic_period_duration_seconds 0.02
`, sn, sn, sn)
		v.Period(20 * time.Millisecond)
		err := testutil.CollectAndCompare(v.period, strings.NewReader(want))
		assert.NoError(t, err)
	})
}
