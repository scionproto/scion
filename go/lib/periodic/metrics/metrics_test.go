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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/prom/promtest"
)

func TestLabels(t *testing.T) {
	tests := []interface{}{
		EventLabels{},
	}
	for _, test := range tests {
		promtest.CheckLabelsStruct(t, test)
	}
}

func TestNewMetric(t *testing.T) {
	n, sn := "randomSnakeName", "random_snake_name"
	assert.NotContains(t, counters, sn)
	x := NewMetric(n)
	assert.Contains(t, counters, sn)
	y := NewMetric(n)
	assert.Equal(t, x, y) // same prefix, same singleton exporter
	z := NewMetric(n + "z")
	assert.NotEqual(t, z, y) // different prefix, not same exporter

	_, ok := x.(ExportMetric)
	assert.True(t, ok)

	v, _ := counters[sn]
	assert.NotNil(t, v.period)
	assert.NotNil(t, v.events)
	assert.NotNil(t, v.runtime)
	assert.NotNil(t, v.timestamp)

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
		//TODO(karampok). the following line does not work until we update the dependency
		// err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		err := collectAndCompare(v.runtime, strings.NewReader(want))
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
		//TODO(karampok). the following line does not work until we update the dependency
		// err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		err := collectAndCompare(v.timestamp, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Event", func(t *testing.T) {
		want := `
# HELP test_me_periodic_event_total Total number of events.
# TYPE test_me_periodic_event_total counter
test_me_periodic_event_total{event_type="kill"} 1
	`
		m.Event(EventKill)
		//TODO(karampok). the following line does not work until we update the dependency
		// err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		err := collectAndCompare(v.events, strings.NewReader(want))
		assert.NoError(t, err)
	})

	t.Run("Period", func(t *testing.T) {
		want := `
# HELP test_me_periodic_period_duration_seconds The period of this job.
# TYPE test_me_periodic_period_duration_seconds gauge
test_me_periodic_period_duration_seconds 0.02
	`
		m.Period(20 * time.Millisecond)
		//TODO(karampok). the following line does not work until we update the dependency
		// err := testutil.CollectAndCompare(v.runtime, strings.NewReader(want))
		err := collectAndCompare(v.period, strings.NewReader(want))
		assert.NoError(t, err)
	})

}
