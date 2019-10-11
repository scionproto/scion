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
		n, sn := "randomSnakeName"+rnd, "random_snake_name_"+rnd
		x := NewMetric(n)
		_, ok := x.(ExportMetric)
		assert.True(t, ok)

		v, _ := counters[sn]
		assert.NotNil(t, v.period)
		assert.NotNil(t, v.events)
		assert.NotNil(t, v.runtime)
		assert.NotNil(t, v.timestamp)
	})

	t.Run("Same name does not panic", func(t *testing.T) {
		n := "randomSnakeNameOne"
		NewMetric(n)
		w := func() {
			NewMetric(n)
		}
		require.NotPanics(t, w)
	})

	t.Run("Invalid name does not panic", func(t *testing.T) {
		n := "random.SnakeName"
		w := func() {
			NewMetric(n)
		}
		require.NotPanics(t, w)
	})
}

func TestContent(t *testing.T) {
	m := NewMetric("testMe")
	v, ok := counters["test_me"]
	assert.True(t, ok)

	t.Run("Runtime", func(t *testing.T) {
		want := `
# HELP test_me_periodic_runtime_duration_seconds_total Total time spend on every periodic run.
# TYPE test_me_periodic_runtime_duration_seconds_total counter
test_me_periodic_runtime_duration_seconds_total 1
	`
		m.Runtime(1 * time.Second)
		err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("StartTimestamp", func(t *testing.T) {
		want := `
# HELP test_me_periodic_runtime_timestamp_seconds The unix timestamp when the periodic run started.
# TYPE test_me_periodic_runtime_timestamp_seconds gauge
test_me_periodic_runtime_timestamp_seconds 1.570633374e+09
	`
		ts := time.Unix(1570633374, 0)
		m.StartTimestamp(ts)
		err := testutil.CollectAndCompare(v.timestamp, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Event", func(t *testing.T) {
		want := `
# HELP test_me_periodic_event_total Total number of events.
# TYPE test_me_periodic_event_total counter
test_me_periodic_event_total{event_type="kill"} 1
	`
		m.Event(EventKill)
		err := testutil.CollectAndCompare(v.events, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Period", func(t *testing.T) {
		want := `
# HELP test_me_periodic_period_duration_seconds The period of this job.
# TYPE test_me_periodic_period_duration_seconds gauge
test_me_periodic_period_duration_seconds 0.02
	`
		m.Period(20 * time.Millisecond)
		err := testutil.CollectAndCompare(v.period, strings.NewReader(want))
		assert.NoError(t, err)
	})
}
