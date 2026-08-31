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
// their contributions. An address resolves through Contributors first,
// then through the domain table; an address matching neither claims nothing.
type Config struct {
	Organizations []string          `json:"organizations"`
	Domains       map[string]string `json:"domains"`
	Contributors  []Contributor     `json:"contributors"`
	IgnoreEmails  []string          `json:"ignoreEmails"`
}

type Contributor struct {
	Name         string        `json:"name"`
	Emails       []string      `json:"emails"`
	Affiliations []Affiliation `json:"affiliations"`
}

// Affiliation binds a contributor to an organization for a span of years.
// From and Until are inclusive. Zero means unbounded.
type Affiliation struct {
	Org   string `json:"org"`
	From  int    `json:"from"`
	Until int    `json:"until"`
}

func (a Affiliation) covers(year int) bool {
	if a.From != 0 && year < a.From {
		return false
	}
	if a.Until != 0 && year > a.Until {
		return false
	}
	return true
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
	for _, con := range c.Contributors {
		if con.Name == "" {
			return fmt.Errorf("contributor with emails %v has no name", con.Emails)
		}
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
		for _, aff := range con.Affiliations {
			if !orgs[aff.Org] {
				return fmt.Errorf("contributor %q maps to undeclared organization %q",
					con.Name, aff.Org)
			}
			if aff.From != 0 && aff.Until != 0 && aff.From > aff.Until {
				return fmt.Errorf(
					"contributor %q has affiliation %q ending before it starts",
					con.Name, aff.Org)
			}
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
}

// NewResolver requires a Config that has passed [Config.validate].
func (c *Config) NewResolver() *Resolver {
	r := &Resolver{
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
		for _, email := range con.Emails {
			r.byEmail[strings.ToLower(email)] = con.Affiliations
		}
	}
	for _, email := range c.IgnoreEmails {
		r.ignored[strings.ToLower(email)] = true
	}
	return r
}

// Org returns the organization holding copyright on a contribution authored by
// email in year. It reports false when nothing may be claimed.
func (r *Resolver) Org(email string, year int) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" || r.ignored[key] {
		return "", false
	}
	if affs, ok := r.byEmail[key]; ok {
		for _, aff := range affs {
			if aff.covers(year) {
				return aff.Org, true
			}
		}
		// Affiliated elsewhere that year.
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
