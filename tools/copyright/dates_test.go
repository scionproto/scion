// Copyright 2026 SCION Association
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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// datedConfig is the configuration the dates in this file refine.
func datedConfig(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{
		Organizations: []string{"SCION Association", "ETH Zurich"},
		Contributors: []Contributor{{
			Name:         "Mover",
			Emails:       []string{"mover@example.com"},
			Affiliations: []string{"ETH Zurich", "SCION Association"},
		}},
	}
	require.NoError(t, cfg.validate())
	return cfg
}

// TestApplyDatesRejects covers the checks that keep a dates file and the
// configuration it refines from drifting apart.
func TestApplyDatesRejects(t *testing.T) {
	testCases := map[string]string{
		"unknown field":                    `[{"nome": "Mover"}]`,
		"nothing dated":                    `[]`,
		"contributor without a name":       `[{"affiliations": [{"org": "ETH Zurich"}]}]`,
		"contributor with no affiliations": `[{"name": "Mover", "affiliations": []}]`,
		"affiliation without an organization": `[
			{"name": "Mover", "affiliations": [{"from": "2018-01-01"}]}
		]`,
		"contributor dated twice": `[
			{"name": "Mover", "affiliations": [{"org": "ETH Zurich"}]},
			{"name": "Mover", "affiliations": [{"org": "SCION Association"}]}
		]`,
		"affiliation ending before it starts": `[
			{"name": "Mover", "affiliations": [
				{"org": "ETH Zurich", "from": "2020-01-01", "until": "2018-12-31"}
			]}
		]`,
		"affiliation bounded by a year rather than a date": `[
			{"name": "Mover", "affiliations": [{"org": "ETH Zurich", "from": "2020"}]}
		]`,
		"affiliation bounded by a date that does not exist": `[
			{"name": "Mover", "affiliations": [{"org": "ETH Zurich", "until": "2021-02-30"}]}
		]`,
		"contributor the configuration does not declare": `[
			{"name": "Stranger", "affiliations": [{"org": "ETH Zurich", "from": "2018-01-01"}]}
		]`,
		"organization the contributor does not have": `[
			{"name": "Mover", "affiliations": [
				{"org": "ETH Zurich"}, {"org": "Anapaya Systems"}
			]}
		]`,
		"organization left out, which would drop claims": `[
			{"name": "Mover", "affiliations": [{"org": "ETH Zurich", "from": "2018-01-01"}]}
		]`,
	}
	for name, raw := range testCases {
		t.Run(name, func(t *testing.T) {
			dates, err := LoadDates([]byte(raw))
			if err != nil {
				return
			}
			assert.Error(t, datedConfig(t).ApplyDates(dates))
		})
	}
}

// TestApplyDates checks that the spans replace the undated affiliations,
// including one organization split into several spans.
func TestApplyDates(t *testing.T) {
	cfg := datedConfig(t)
	dates, err := LoadDates([]byte(`[
		{"name": "Mover", "affiliations": [
			{"org": "ETH Zurich", "from": "2018-01-01", "until": "2019-12-31"},
			{"org": "SCION Association", "from": "2020-01-01", "until": "2020-12-31"},
			{"org": "ETH Zurich", "from": "2021-01-01"}
		]}
	]`))
	require.NoError(t, err)
	require.NoError(t, cfg.ApplyDates(dates))
	r := cfg.NewResolver()

	for date, want := range map[string]string{
		"2017-12-31": "",
		"2018-06-01": "ETH Zurich",
		"2020-06-01": "SCION Association",
		"2024-06-01": "ETH Zurich",
	} {
		org, ok := r.Org("mover@example.com", date)
		assert.Equal(t, want, org, date)
		assert.Equal(t, want != "", ok, date)
	}
}

// TestUndatedAffiliationCoversEveryDay checks the configuration on its own:
// without a dates file, nothing bounds an affiliation.
func TestUndatedAffiliationCoversEveryDay(t *testing.T) {
	r := datedConfig(t).NewResolver()
	for _, date := range []string{"2014-01-01", "2024-06-01", "2099-12-31"} {
		org, ok := r.Org("mover@example.com", date)
		assert.True(t, ok, date)
		// The first affiliation listed answers for every day.
		assert.Equal(t, "ETH Zurich", org, date)
	}
}
