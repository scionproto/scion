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
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"
)

//go:embed affiliations.json
var embeddedConfig []byte

// Config maps git author identities to the organizations holding copyright on
// their contributions. An address resolves through Contributors first, then
// through the domain table. An address matching neither claims nothing.
//
// Config carries no dates: an affiliation covers every day its contributor
// worked. [Dates] refines that, and is optional.
type Config struct {
	// Since freezes the history before that day: an earlier contribution is not
	// attributed at all. The headers already record it, and a claim is never
	// taken back, so reading that history again can only re-attribute it. A run
	// without a [Dates] file would do exactly that, every affiliation covering
	// every day. Advance the cutoff whenever the dates are applied, so a [Dates]
	// file only has to cover the span before it.
	// An empty value puts the whole history in scope, and then -dates is required.
	Since string `json:"since"`

	Organizations []string          `json:"organizations"`
	Domains       map[string]string `json:"domains"`
	Contributors  []Contributor     `json:"contributors"`
	IgnoreEmails  []string          `json:"ignoreEmails"`

	// dated holds the spans read from an optional [Dates] file, by contributor
	// name. [Config.ApplyDates] fills it. [Config.NewResolver] prefers it over
	// the undated affiliations.
	dated map[string][]Affiliation
}

// Contributor names the organizations holding copyright on one person's work.
// Affiliations are organization names. Without a [Dates] file the first one
// answers for every day, so the current organization comes first.
type Contributor struct {
	Name         string   `json:"name"`
	Emails       []string `json:"emails"`
	Affiliations []string `json:"affiliations"`
}

// LoadConfig parses raw, or the embedded configuration if raw is nil.
func LoadConfig(raw []byte) (*Config, error) {
	if raw == nil {
		raw = embeddedConfig
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing affiliations: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate rejects a configuration that would misattribute work.
func (c *Config) validate() error {
	if c.Since != "" {
		// A malformed cutoff compares wrongly against a commit date, putting
		// more of the history back in scope than was meant.
		if _, err := time.Parse(time.DateOnly, c.Since); err != nil {
			return fmt.Errorf("since %q is not a day in YYYY-MM-DD form", c.Since)
		}
	}
	if len(c.Organizations) == 0 {
		return fmt.Errorf("no organizations declared")
	}
	orgs := make(map[string]bool, len(c.Organizations))
	for _, org := range c.Organizations {
		if org != strings.TrimSpace(org) || org == "" {
			return fmt.Errorf("organization %q is empty or badly spaced", org)
		}
		if strings.Contains(org, ",") {
			// [splitHolders] splits a shared line on commas.
			return fmt.Errorf("organization %q must not contain a comma", org)
		}
		if orgs[org] {
			return fmt.Errorf("organization %q declared twice", org)
		}
		orgs[org] = true
	}
	for domain, org := range c.Domains {
		if !orgs[org] {
			return fmt.Errorf("domain %q maps to undeclared organization %q", domain, org)
		}
		if domain != strings.ToLower(domain) {
			return fmt.Errorf("domain %q must be lowercase", domain)
		}
	}
	seen := make(map[string]string)
	// A [Dates] file refers to contributors by name, so names must be unique.
	names := make(map[string]bool, len(c.Contributors))
	for _, con := range c.Contributors {
		if con.Name == "" {
			return fmt.Errorf("contributor with emails %v has no name", con.Emails)
		}
		if names[con.Name] {
			return fmt.Errorf("contributor %q declared twice", con.Name)
		}
		names[con.Name] = true
		if len(con.Emails) == 0 {
			return fmt.Errorf("contributor %q has no emails", con.Name)
		}
		if len(con.Affiliations) == 0 {
			return fmt.Errorf("contributor %q has no affiliations", con.Name)
		}
		for _, email := range con.Emails {
			key := strings.ToLower(email)
			if other, ok := seen[key]; ok {
				return fmt.Errorf("email %q claimed by both %q and %q",
					email, other, con.Name)
			}
			seen[key] = con.Name
		}
		claimed := make(map[string]bool, len(con.Affiliations))
		for _, org := range con.Affiliations {
			if !orgs[org] {
				return fmt.Errorf("contributor %q maps to undeclared organization %q",
					con.Name, org)
			}
			if claimed[org] {
				return fmt.Errorf("contributor %q lists organization %q twice",
					con.Name, org)
			}
			claimed[org] = true
		}
	}
	return nil
}

// Resolver answers which organization holds copyright on a contribution.
type Resolver struct {
	byEmail map[string][]Affiliation
	domains map[string]string
	ignored map[string]bool
	orgs    map[string]string
	since   string
}

// NewResolver requires a Config that has passed [Config.validate].
func (c *Config) NewResolver() *Resolver {
	r := &Resolver{
		since:   c.Since,
		byEmail: make(map[string][]Affiliation),
		domains: make(map[string]string, len(c.Domains)),
		ignored: make(map[string]bool, len(c.IgnoreEmails)),
		orgs:    make(map[string]string, len(c.Organizations)),
	}
	for _, org := range c.Organizations {
		r.orgs[strings.ToLower(org)] = org
	}
	maps.Copy(r.domains, c.Domains)
	for _, con := range c.Contributors {
		affs, ok := c.dated[con.Name]
		if !ok {
			affs = make([]Affiliation, 0, len(con.Affiliations))
			for _, org := range con.Affiliations {
				affs = append(affs, Affiliation{Org: org})
			}
		}
		for _, email := range con.Emails {
			r.byEmail[strings.ToLower(email)] = affs
		}
	}
	for _, email := range c.IgnoreEmails {
		r.ignored[strings.ToLower(email)] = true
	}
	return r
}

// Frozen reports whether date falls before the cutoff. Skipping such a
// contribution keeps a run without a [Dates] file from re-attributing work the
// headers already record, and from reporting its author as a gap.
// Dates in YYYY-MM-DD form sort lexicographically, so no parsing is needed.
func (r *Resolver) Frozen(date string) bool {
	return r.since != "" && date < r.since
}

// Org returns the organization holding copyright on a contribution authored by
// email on date. It reports false when nothing may be claimed.
func (r *Resolver) Org(email, date string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" || r.ignored[key] {
		return "", false
	}
	if affs, ok := r.byEmail[key]; ok {
		for _, aff := range affs {
			if aff.covers(date) {
				return aff.Org, true
			}
		}
		// Affiliated elsewhere that day.
		// An explicit entry must not fall through to the domain rule below.
		return "", false
	}
	if _, domain, ok := strings.Cut(key, "@"); ok {
		if org, ok := r.domains[domain]; ok {
			return org, true
		}
	}
	return "", false
}

// Known reports whether the configuration mentions an address at all,
// however [Resolver.Org] answers for it. The report lists unknown addresses as gaps.
func (r *Resolver) Known(email string) bool {
	key := strings.ToLower(strings.TrimSpace(email))
	if _, ok := r.byEmail[key]; ok {
		return true
	}
	if r.ignored[key] {
		return true
	}
	_, domain, ok := strings.Cut(key, "@")
	if !ok {
		return false
	}
	_, ok = r.domains[domain]
	return ok
}

// KnownOrg canonicalizes an organization name read from a copyright line.
// It reports false for undeclared holders, which is how third-party notices are detected.
func (r *Resolver) KnownOrg(holder string) (string, bool) {
	org, ok := r.orgs[strings.ToLower(strings.TrimSpace(holder))]
	return org, ok
}
