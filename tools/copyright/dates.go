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
	"slices"
	"strings"
	"time"
)

// Dates dates the affiliations of a [Config]. It is optional and, unlike
// affiliations.json, not embedded: the repository does not publish when a
// person worked where. Without it every affiliation covers every day, and
// [Config.Since] alone limits which history such a run reads.
//
// A file lists contributors the configuration declares, with the same
// organizations, in the order to try them:
//
//	[
//	  {
//	    "name": "Some Contributor",
//	    "affiliations": [
//	      {"org": "ETH Zurich", "from": "2018-09-01", "until": "2022-11-30"},
//	      {"org": "SCION Association", "from": "2022-12-01"}
//	    ]
//	  }
//	]
type Dates []DatedContributor

// DatedContributor dates the affiliations of one contributor of a [Config],
// found by name. One organization may be split into several spans. The set of
// organizations must be the one the configuration declares.
type DatedContributor struct {
	Name         string        `json:"name"`
	Affiliations []Affiliation `json:"affiliations"`
}

// Affiliation is an organization and the span of days it holds copyright for.
// From and Until are inclusive dates in YYYY-MM-DD form.
// An empty string is an open end, so the zero value covers every day.
type Affiliation struct {
	Org   string `json:"org"`
	From  string `json:"from,omitempty"`
	Until string `json:"until,omitempty"`
}

// covers reports whether a contribution made on date falls in the span.
// Dates in this form sort lexicographically, so no parsing is needed:
// [Dates.validate] has already rejected every other shape.
func (a Affiliation) covers(date string) bool {
	if a.From != "" && date < a.From {
		return false
	}
	if a.Until != "" && date > a.Until {
		return false
	}
	return true
}

// LoadDates parses raw. [Config.ApplyDates] validates the result, on its own
// and against the configuration it refines.
func LoadDates(raw []byte) (Dates, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Dates
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("parsing affiliation dates: %w", err)
	}
	return d, nil
}

func (d Dates) validate() error {
	if len(d) == 0 {
		return fmt.Errorf("no contributors dated")
	}
	seen := make(map[string]bool, len(d))
	for _, con := range d {
		if con.Name == "" {
			return fmt.Errorf("dated contributor with affiliations %v has no name",
				con.Affiliations)
		}
		if seen[con.Name] {
			return fmt.Errorf("contributor %q dated twice", con.Name)
		}
		seen[con.Name] = true
		if len(con.Affiliations) == 0 {
			return fmt.Errorf("contributor %q has no affiliations", con.Name)
		}
		for _, aff := range con.Affiliations {
			if aff.Org == "" {
				return fmt.Errorf("contributor %q has an affiliation without an organization",
					con.Name)
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
			if aff.From != "" && aff.Until != "" && aff.From > aff.Until {
				return fmt.Errorf(
					"contributor %q has affiliation %q ending before it starts",
					con.Name, aff.Org)
			}
		}
	}
	return nil
}

// ApplyDates gives the contributors of c the spans in d. c must have passed
// [Config.validate]. A file that has drifted from the configuration is
// rejected: dating someone it does not declare, or an organization it does not
// give them, changes who holds copyright on their work.
func (c *Config) ApplyDates(d Dates) error {
	if err := d.validate(); err != nil {
		return err
	}
	byName := make(map[string][]string, len(c.Contributors))
	for _, con := range c.Contributors {
		byName[con.Name] = con.Affiliations
	}
	dated := make(map[string][]Affiliation, len(d))
	for _, con := range d {
		undated, ok := byName[con.Name]
		if !ok {
			return fmt.Errorf("dates given for %q, who is not a known contributor",
				con.Name)
		}
		orgs := make([]string, 0, len(con.Affiliations))
		for _, aff := range con.Affiliations {
			if !slices.Contains(undated, aff.Org) {
				return fmt.Errorf("dates put %q at %q, which is not one of their "+
					"organizations (%s)",
					con.Name, aff.Org, strings.Join(undated, ", "))
			}
			if !slices.Contains(orgs, aff.Org) {
				orgs = append(orgs, aff.Org)
			}
		}
		for _, org := range undated {
			if !slices.Contains(orgs, org) {
				return fmt.Errorf("dates leave out %q of %q, "+
					"whose work would stop being claimed for it",
					org, con.Name)
			}
		}
		dated[con.Name] = con.Affiliations
	}
	c.dated = dated
	return nil
}
