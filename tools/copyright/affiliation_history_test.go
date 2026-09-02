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

// historyConfig is the configuration an affiliation history stands in for.
// Its contributors are the people working here now, which a rewrite of older
// history reaches back past, so the history names someone it does not.
func historyConfig(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{
		Organizations: []string{"SCION Association", "ETH Zurich"},
		Contributors: []Contributor{{
			Name:        "Stayer",
			Emails:      []string{"stayer@example.com"},
			Affiliation: "SCION Association",
		}},
	}
	require.NoError(t, cfg.validate())
	return cfg
}

// TestApplyHistoryRejects covers the validation of a file that has to stand on its own,
// and of the organizations it may name.
func TestApplyHistoryRejects(t *testing.T) {
	testCases := map[string]string{
		"unknown field":              `[{"nome": "Mover"}]`,
		"nobody covered":             `[]`,
		"contributor without a name": `[{"emails": ["m@x"], "affiliations": []}]`,
		"contributor without emails": `[
			{"name": "Mover", "affiliations": [
				{"org": "ETH Zurich", "from": "2018-01-01"}
			]}
		]`,
		"contributor with no affiliations": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": []}
		]`,
		"affiliation without an organization": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"from": "2018-01-01"}
			]}
		]`,
		"affiliation without a from day": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich"}
			]}
		]`,
		"contributor listed twice": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich", "from": "2018-01-01"}
			]},
			{"name": "Mover", "emails": ["m@y"], "affiliations": [
				{"org": "SCION Association", "from": "2023-01-01"}
			]}
		]`,
		"email claimed twice": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich", "from": "2018-01-01"}
			]},
			{"name": "Other", "emails": ["M@X"], "affiliations": [
				{"org": "SCION Association", "from": "2023-01-01"}
			]}
		]`,
		"affiliation ending before it starts": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich", "from": "2020-01-01", "until": "2018-12-31"}
			]}
		]`,
		"affiliation bounded by a year rather than a date": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich", "from": "2020"}
			]}
		]`,
		"affiliation bounded by a date that does not exist": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "ETH Zurich", "from": "2020-01-01", "until": "2021-02-30"}
			]}
		]`,
		"undeclared organization": `[
			{"name": "Mover", "emails": ["m@x"], "affiliations": [
				{"org": "Anapaya Systems", "from": "2018-01-01"}
			]}
		]`,
	}
	for name, raw := range testCases {
		t.Run(name, func(t *testing.T) {
			history, err := LoadAffiliationHistory([]byte(raw))
			if err != nil {
				return
			}
			assert.Error(t, historyConfig(t).ApplyHistory(history))
		})
	}
}

// TestApplyHistory checks that the history answers on its own: for a
// contributor the configuration no longer lists, through the addresses it
// carries itself, including an organization since left and one split into
// several spans.
func TestApplyHistory(t *testing.T) {
	cfg := historyConfig(t)
	history, err := LoadAffiliationHistory([]byte(`[
		{"name": "Mover", "emails": ["mover@example.com"], "affiliations": [
			{"org": "ETH Zurich", "from": "2018-01-01", "until": "2019-12-31"},
			{"org": "SCION Association", "from": "2020-01-01", "until": "2020-12-31"},
			{"org": "ETH Zurich", "from": "2021-01-01"}
		]}
	]`))
	require.NoError(t, err)
	require.NoError(t, cfg.ApplyHistory(history))
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

// TestHistoryReplacesTheSnapshot checks the mutual exclusion: with a history applied,
// a contributor of the configuration it leaves out is not attributed
// from the snapshot, and is reported as a gap like any other unknown address.
func TestHistoryReplacesTheSnapshot(t *testing.T) {
	cfg := historyConfig(t)
	r := cfg.NewResolver()
	org, ok := r.Org("stayer@example.com", "2026-06-01")
	require.True(t, ok, "the snapshot answers on its own")
	require.Equal(t, "SCION Association", org)

	history, err := LoadAffiliationHistory([]byte(`[
		{"name": "Mover", "emails": ["mover@example.com"], "affiliations": [
			{"org": "ETH Zurich", "from": "2018-01-01"}
		]}
	]`))
	require.NoError(t, err)
	require.NoError(t, cfg.ApplyHistory(history))
	r = cfg.NewResolver()

	_, ok = r.Org("stayer@example.com", "2026-06-01")
	assert.False(t, ok, "the history answers alone, and does not date this one")
	assert.False(t, r.Known("stayer@example.com"),
		"so the run reports the address, rather than claiming nothing in silence")
}

// TestSnapshotAffiliationCoversEveryDay checks the configuration on its own:
// without an affiliation history, nothing bounds an affiliation.
func TestSnapshotAffiliationCoversEveryDay(t *testing.T) {
	r := historyConfig(t).NewResolver()
	for _, date := range []string{"2014-01-01", "2024-06-01", "2099-12-31"} {
		org, ok := r.Org("stayer@example.com", date)
		assert.True(t, ok, date)
		assert.Equal(t, "SCION Association", org, date)
	}
}
