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

// TestEmbeddedConfig checks that affiliations.json loads and validates.
// A typo in it fails here rather than in a checkout.
func TestEmbeddedConfig(t *testing.T) {
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	assert.NotEmpty(t, cfg.Organizations)
	assert.NotEmpty(t, cfg.Domains)
	assert.NotEmpty(t, cfg.Contributors)
}

// TestLoadConfigRejects covers the validation that stops a mistyped
// configuration from misattributing work.
func TestLoadConfigRejects(t *testing.T) {
	testCases := map[string]string{
		"no organizations": `{"organizations": []}`,
		"unknown field":    `{"organizations": ["A"], "orgnisations": []}`,
		"the since cutoff, which no longer exists": `{
			"since": "2026-09-01",
			"organizations": ["A"]
		}`,
		"organization with a comma": `{
			"organizations": ["Some Corp, Inc."]
		}`,
		"domain of an undeclared organization": `{
			"organizations": ["A"],
			"domains": {"a.example": "B"}
		}`,
		"uppercase domain": `{
			"organizations": ["A"],
			"domains": {"A.example": "A"}
		}`,
		"contributor of an undeclared organization": `{
			"organizations": ["A"],
			"contributors": [
				{"name": "N", "emails": ["n@x"], "affiliation": "B"}
			]
		}`,
		"contributor without an affiliation": `{
			"organizations": ["A"],
			"contributors": [{"name": "N", "emails": ["n@x"], "affiliation": ""}]
		}`,
		"email claimed twice": `{
			"organizations": ["A"],
			"contributors": [
				{"name": "N", "emails": ["n@x"], "affiliation": "A"},
				{"name": "M", "emails": ["N@X"], "affiliation": "A"}
			]
		}`,
		"contributor declared twice": `{
			"organizations": ["A"],
			"contributors": [
				{"name": "N", "emails": ["n@x"], "affiliation": "A"},
				{"name": "N", "emails": ["n@y"], "affiliation": "A"}
			]
		}`,
		"several affiliations, which belong in an affiliation history": `{
			"organizations": ["A"],
			"contributors": [
				{"name": "N", "emails": ["n@x"], "affiliations": ["A"]}
			]
		}`,
		"dated affiliation, which belongs in an affiliation history": `{
			"organizations": ["A"],
			"contributors": [
				{"name": "N", "emails": ["n@x"],
				 "affiliation": {"org": "A", "from": "2020-01-01"}}
			]
		}`,
	}
	for name, raw := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig([]byte(raw))
			assert.Error(t, err)
		})
	}
}

func TestResolverOrg(t *testing.T) {
	r := testResolver(t)
	testCases := map[string]struct {
		email string
		date  string
		org   string
	}{
		"by domain": {
			email: "who@anapaya.net", date: "2020-06-01", org: "Anapaya Systems",
		},
		"domain case is irrelevant": {
			email: "Who@Anapaya.NET", date: "2020-06-01", org: "Anapaya Systems",
		},
		"unknown domain": {
			email: "who@example.com", date: "2020-06-01", org: "",
		},
		"mover, before the move": {
			email: "mover@example.com", date: "2020-06-01", org: "ETH Zurich",
		},
		"mover, after the move": {
			email: "mover@example.com", date: "2024-06-01", org: "SCION Association",
		},
		"mover, between affiliations": {
			email: "mover@example.com", date: "2017-06-01", org: "",
		},
		"mover, on the first day of an affiliation": {
			email: "mover@example.com", date: "2018-01-01", org: "ETH Zurich",
		},
		"mover, on the last day of an affiliation": {
			email: "mover@example.com", date: "2022-12-31", org: "ETH Zurich",
		},
		"mover, the day after an affiliation ends": {
			email: "mover@example.com", date: "2023-01-01", org: "SCION Association",
		},
		"ignored address": {
			email: "bot@example.com", date: "2024-06-01", org: "",
		},
		"not an address": {
			email: "nobody", date: "2024-06-01", org: "",
		},
		"empty": {
			email: "", date: "2024-06-01", org: "",
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			org, ok := r.Org(tc.email, tc.date)
			assert.Equal(t, tc.org, org)
			assert.Equal(t, tc.org != "", ok)
		})
	}
}

// TestResolverKnown checks the distinction the report relies on: an unknown
// address is a gap to fill, an address left unaffiliated in some year is not.
func TestResolverKnown(t *testing.T) {
	r := testResolver(t)
	assert.True(t, r.Known("mover@example.com"))
	assert.True(t, r.Known("who@anapaya.net"))
	assert.True(t, r.Known("bot@example.com"))
	assert.False(t, r.Known("stranger@example.com"))
	assert.False(t, r.Known("nobody"))
}

func TestKnownOrg(t *testing.T) {
	r := testResolver(t)
	org, ok := r.KnownOrg(" scion association ")
	require.True(t, ok)
	require.Equal(t, "SCION Association", org)
	_, ok = r.KnownOrg("Some Other Corp")
	require.False(t, ok)
}
