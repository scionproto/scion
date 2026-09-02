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
)

//go:embed affiliations.json
var embeddedConfig []byte

// Config maps git author identities to the organizations holding copyright on
// their contributions. An address resolves through Contributors first, then
// through the domain table. An address matching neither claims nothing.
//
// Config describes the present: where each contributor works at the time of the run.
// It carries no dates, so an affiliation covers every day. Rewriting older
// history needs the days themselves, and those live in an [AffiliationHistory] file.
// The two are mutually exclusive: a run reads either this snapshot or
// that history, never both.
type Config struct {
	Organizations []string          `json:"organizations"`
	Domains       map[string]string `json:"domains"`
	Contributors  []Contributor     `json:"contributors"`
	IgnoreEmails  []string          `json:"ignoreEmails"`

	// history is an [AffiliationHistory] file, which carries its own addresses.
	// [Config.ApplyHistory] fills it, and [Config.NewResolver] then answers
	// from it alone, in place of Contributors.
	history AffiliationHistory
}

// Contributor names the organization holding copyright on one person's work today.
// Affiliation is an organization name and answers for every day that
// person contributed; an [AffiliationHistory] file replaces the whole list of
// them with dated spans. Someone who has stopped contributing is dropped from the list,
// and lives on in that history.
type Contributor struct {
	Name        string   `json:"name"`
	Emails      []string `json:"emails"`
	Affiliation string   `json:"affiliation"`
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
	// An [AffiliationHistory] file refers to contributors by name,
	// so names must be unique.
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
		if con.Affiliation == "" {
			return fmt.Errorf("contributor %q has no affiliation", con.Name)
		}
		if !orgs[con.Affiliation] {
			return fmt.Errorf("contributor %q maps to undeclared organization %q",
				con.Name, con.Affiliation)
		}
		for _, email := range con.Emails {
			key := strings.ToLower(email)
			if other, ok := seen[key]; ok {
				return fmt.Errorf("email %q claimed by both %q and %q",
					email, other, con.Name)
			}
			seen[key] = con.Name
		}
	}
	return nil
}

// Resolver answers which organization holds copyright on a contribution.
type Resolver struct {
	byEmail map[string][]AffiliationSpan
	domains map[string]string
	ignored map[string]bool
	orgs    map[string]string
}

// NewResolver requires a Config that has passed [Config.validate].
func (c *Config) NewResolver() *Resolver {
	r := &Resolver{
		byEmail: make(map[string][]AffiliationSpan),
		domains: make(map[string]string, len(c.Domains)),
		ignored: make(map[string]bool, len(c.IgnoreEmails)),
		orgs:    make(map[string]string, len(c.Organizations)),
	}
	for _, org := range c.Organizations {
		r.orgs[strings.ToLower(org)] = org
	}
	maps.Copy(r.domains, c.Domains)
	if c.history != nil {
		// The history answers for every day it dates, and for no other.
		for _, con := range c.history {
			for _, email := range con.Emails {
				r.byEmail[strings.ToLower(email)] = con.Affiliations
			}
		}
	} else {
		// A span with no bounds covers every day, which is how the snapshot answers:
		// it says where people work now, not since when.
		for _, con := range c.Contributors {
			affs := []AffiliationSpan{{Org: con.Affiliation}}
			for _, email := range con.Emails {
				r.byEmail[strings.ToLower(email)] = affs
			}
		}
	}
	for _, email := range c.IgnoreEmails {
		r.ignored[strings.ToLower(email)] = true
	}
	return r
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
