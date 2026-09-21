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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AffiliationHistory says who held copyright on which contribution, and when,
// for a run that rewrites the copyright lines of older history. It is optional and,
// unlike affiliations.json, not embedded: the repository does not publish
// when a person worked where.
//
// It replaces the contributors of a [Config] rather than refining them:
// a run reads either the snapshot or this history, never both. So it carries the
// addresses itself, and stands alone. affiliations.json lists only the people
// contributing now, and a rewrite reaches back past all of them,
// which is why the two cannot be halves of one answer.
//
// Only Organizations, Domains and IgnoreEmails are still read from the
// configuration: those hold whenever an address was used.
//
//	[
//	  {
//	    "name": "Some Contributor",
//	    "emails": ["some@example.com"],
//	    "affiliations": [
//	      {"org": "ETH Zurich", "from": "2018-09-01", "until": "2022-11-30"},
//	      {"org": "SCION Association", "from": "2022-12-01"}
//	    ]
//	  }
//	]
type AffiliationHistory []ContributorHistory

// ContributorHistory dates the affiliations of one contributor.
// One organization may be split into several spans, and an organization the
// contributor has since left belongs here as much as the current one.
// Name labels the entry; the addresses are what a contribution is matched by.
type ContributorHistory struct {
	Name         string            `json:"name"`
	Emails       []string          `json:"emails"`
	Affiliations []AffiliationSpan `json:"affiliations"`
}

// AffiliationSpan is an organization and the span of days it holds copyright
// for. From and Until are inclusive dates in YYYY-MM-DD form.
// From is required, so that no span reaches further back than it was meant to;
// Until may be omitted for an affiliation that still holds.
type AffiliationSpan struct {
	Org   string `json:"org"`
	From  string `json:"from,omitempty"`
	Until string `json:"until,omitempty"`
}

// covers reports whether a contribution made on date falls in the span.
// Dates in this form sort lexicographically, so no parsing is needed:
// [AffiliationHistory.validate] has already rejected every other shape.
func (a AffiliationSpan) covers(date string) bool {
	if a.From != "" && date < a.From {
		return false
	}
	if a.Until != "" && date > a.Until {
		return false
	}
	return true
}

// LoadAffiliationHistory parses raw. [Config.ApplyHistory] validates the result,
// on its own and against the organizations the configuration declares.
func LoadAffiliationHistory(raw []byte) (AffiliationHistory, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var h AffiliationHistory
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("parsing affiliation history: %w", err)
	}
	return h, nil
}

func (h AffiliationHistory) validate() error {
	if len(h) == 0 {
		return fmt.Errorf("no contributors in the affiliation history")
	}
	names := make(map[string]bool, len(h))
	seen := make(map[string]string)
	for _, con := range h {
		if con.Name == "" {
			return fmt.Errorf("contributor with affiliations %v has no name",
				con.Affiliations)
		}
		if names[con.Name] {
			return fmt.Errorf("contributor %q listed twice", con.Name)
		}
		names[con.Name] = true
		if len(con.Emails) == 0 {
			return fmt.Errorf("contributor %q has no emails", con.Name)
		}
		for _, email := range con.Emails {
			key := strings.ToLower(email)
			if other, ok := seen[key]; ok {
				return fmt.Errorf("email %q claimed by both %q and %q",
					email, other, con.Name)
			}
			seen[key] = con.Name
		}
		if len(con.Affiliations) == 0 {
			return fmt.Errorf("contributor %q has no affiliations", con.Name)
		}
		for _, aff := range con.Affiliations {
			if aff.Org == "" {
				return fmt.Errorf("contributor %q has an affiliation without an organization",
					con.Name)
			}
			if aff.From == "" {
				// An open start would claim work from before this repository existed.
				// Where the day is unknown, -01-01 says the year.
				return fmt.Errorf("contributor %q has affiliation %q without a \"from\" day",
					con.Name, aff.Org)
			}
			for _, bound := range []string{aff.From, aff.Until} {
				if bound == "" {
					continue
				}
				if _, err := time.Parse(time.DateOnly, bound); err != nil {
					return fmt.Errorf(
						"contributor %q has affiliation %q with date %q, want YYYY-MM-DD",
						con.Name, aff.Org, bound)
				}
			}
			if aff.Until != "" && aff.From > aff.Until {
				return fmt.Errorf(
					"contributor %q has affiliation %q ending before it starts",
					con.Name, aff.Org)
			}
		}
	}
	return nil
}

// ApplyHistory puts h in place of the contributors of c, which must have
// passed [Config.validate]. Every organization h names has to be one the
// configuration declares: any other is a holder this repository never claims for,
// and a typo would quietly become one.
func (c *Config) ApplyHistory(h AffiliationHistory) error {
	if err := h.validate(); err != nil {
		return err
	}
	orgs := make(map[string]bool, len(c.Organizations))
	for _, org := range c.Organizations {
		orgs[org] = true
	}
	for _, con := range h {
		for _, aff := range con.Affiliations {
			if !orgs[aff.Org] {
				return fmt.Errorf("affiliation history puts %q at undeclared "+
					"organization %q", con.Name, aff.Org)
			}
		}
	}
	c.history = h
	return nil
}
