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
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// claimLine matches "// Copyright <year> <holder>[, <holder>...]",
// the form the goheader linter in .golangci.yml enforces.
var claimLine = regexp.MustCompile(`^// Copyright (20[0-9]{2}) (\S.*?)\s*$`)

var (
	generatedMarker = regexp.MustCompile(`(?i)^// Code generated .* DO NOT EDIT\.?$`)
	licenseMarker   = "// Licensed under the Apache License"
)

type claim struct {
	year    int
	holders []string
}

func (c claim) String() string {
	return fmt.Sprintf("// Copyright %d %s", c.year, strings.Join(c.holders, ", "))
}

// header is the copyright block at the top of a file.
type header struct {
	claims []claim
	// end is the index of the first line below the claims.
	// Zero means the file has none, and that they belong at the top.
	end int
	// separate appends the blank comment line goheader requires between the
	// claims and the license text.
	separate bool
}

// skipReason explains why a file is left alone.
// The empty value means it can be processed.
type skipReason string

const (
	skipGenerated   skipReason = "generated file"
	skipNoHeader    skipReason = "no copyright header and no license block"
	skipForeign     skipReason = "unrecognized copyright notice, possibly third-party"
	skipUnknownOrgs skipReason = "copyright held by an organization not in the configuration"
)

// parseHeader locates the copyright claims in lines. It refuses any notice it does not
// fully recognize: mangling a third-party notice is worse than leaving it outdated.
func parseHeader(lines []string, r *Resolver) (*header, skipReason) {
	// Only the leading run of "//" lines can hold a notice.
	// Code below can mention copyright in a string or a comment of its own.
	block := 0
	for block < len(lines) && strings.HasPrefix(lines[block], "//") {
		if generatedMarker.MatchString(strings.TrimSpace(lines[block])) {
			return nil, skipGenerated
		}
		block++
	}

	// Claims lead the comment block. Anything below them, an SPDX identifier
	// included, is left where it is.
	var claims []claim
	end := 0
	for end < block {
		m := claimLine.FindStringSubmatch(lines[end])
		if m == nil {
			break
		}
		year, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, skipForeign
		}
		holders, ok := splitHolders(m[2], r)
		if !ok {
			return nil, skipUnknownOrgs
		}
		claims = append(claims, claim{year: year, holders: holders})
		end++
	}

	// Copyright mentioned outside the parsed claims belongs to someone else.
	for i := range block {
		if i < end {
			continue
		}
		if mentionsCopyright(lines[i]) {
			return nil, skipForeign
		}
	}

	if len(claims) == 0 {
		// A missing license is not invented here. goheader flags it.
		for i := range block {
			if strings.HasPrefix(lines[i], licenseMarker) {
				return &header{separate: strings.TrimSpace(lines[0]) != "//"}, ""
			}
		}
		return nil, skipNoHeader
	}
	return &header{claims: claims, end: end}, ""
}

func mentionsCopyright(line string) bool {
	return strings.Contains(line, "Copyright") || strings.Contains(line, "copyright")
}

// splitHolders parses the holder part of a copyright line. Holders may share a
// line ("SCION Association, Anapaya Systems"), but only if every part is a
// configured organization.
func splitHolders(text string, r *Resolver) ([]string, bool) {
	parts := strings.Split(text, ",")
	holders := make([]string, 0, len(parts))
	for _, part := range parts {
		org, ok := r.KnownOrg(part)
		if !ok {
			return nil, false
		}
		holders = append(holders, org)
	}
	return holders, true
}

// update folds contributions into the existing claims.
// It never drops a claim and never moves a year back:
// git history is not the only evidence of authorship.
func (h *header) update(contributions map[string]int) []claim {
	claims := make([]claim, 0, len(h.claims)+len(contributions))
	for _, c := range h.claims {
		claims = append(claims, claim{year: c.year, holders: slices.Clone(c.holders)})
	}

	claimed := claimedYears(claims)
	for _, org := range slices.Sorted(maps.Keys(contributions)) {
		year := contributions[org]
		if claimed[org] >= year {
			continue
		}
		if _, ok := claimed[org]; ok {
			claims = bumpHolder(claims, org, year)
			continue
		}
		claims = append(claims, claim{year: year, holders: []string{org}})
	}

	// Newest first, and stable, so claims of equal year keep the order they had
	// and an untouched header is never reshuffled.
	slices.SortStableFunc(claims, func(a, b claim) int {
		return cmp.Compare(b.year, a.year)
	})
	return claims
}

// claimedYears is the highest year each organization already claims.
func claimedYears(claims []claim) map[string]int {
	claimed := make(map[string]int)
	for _, c := range claims {
		for _, holder := range c.holders {
			if c.year > claimed[holder] {
				claimed[holder] = c.year
			}
		}
	}
	return claimed
}

// reasons explains the claim lines an update produced, keyed by the rendered line.
// Only lines the update moved get an entry: an untouched line needs no justification.
// A line shared by several organizations names each of them.
func reasons(old, updated []claim, attr map[string]attribution) map[string]string {
	was := claimedYears(old)
	out := make(map[string]string)
	for _, c := range updated {
		var parts []string
		for _, org := range c.holders {
			a, ok := attr[org]
			if !ok || a.year != c.year || was[org] >= c.year {
				// This holder was already claiming the year,
				// so the line moved for somebody else on it.
				continue
			}
			parts = append(parts, fmt.Sprintf("%s: %s", org, a))
		}
		switch len(parts) {
		case 0:
		case 1:
			// Naming the one holder again would only repeat the line.
			_, evidence, _ := strings.Cut(parts[0], ": ")
			out[c.String()] = evidence
		default:
			out[c.String()] = strings.Join(parts, "; ")
		}
	}
	return out
}

// bumpHolder moves org's newest claim to year.
// A shared line splits, which leaves the other holders' year unchanged.
func bumpHolder(claims []claim, org string, year int) []claim {
	best := -1
	for i, c := range claims {
		if !slices.Contains(c.holders, org) {
			continue
		}
		if best == -1 || c.year > claims[best].year {
			best = i
		}
	}
	if best == -1 {
		return append(claims, claim{year: year, holders: []string{org}})
	}
	if len(claims[best].holders) == 1 {
		claims[best].year = year
		return claims
	}
	claims[best].holders = remove(claims[best].holders, org)
	// Join an existing line for the same year rather than adding a second one.
	for i, c := range claims {
		if c.year == year && i != best {
			claims[i].holders = insertHolder(c.holders, org)
			return claims
		}
	}
	return append(claims, claim{year: year, holders: []string{org}})
}

// insertHolder appends org to a shared line unless it is already there.
func insertHolder(holders []string, org string) []string {
	if slices.Contains(holders, org) {
		return holders
	}
	return append(slices.Clone(holders), org)
}

// remove returns holders without org. The clone matters:
// holders is shared with the claim this one was split from.
func remove(holders []string, org string) []string {
	return slices.DeleteFunc(slices.Clone(holders), func(h string) bool {
		return h == org
	})
}

// render returns lines with the claim block replaced by claims.
func (h *header) render(lines []string, claims []claim) []string {
	rendered := make([]string, 0, len(claims))
	for _, c := range claims {
		if len(c.holders) == 0 {
			// All holders moved to a newer line.
			continue
		}
		rendered = append(rendered, c.String())
	}
	if h.separate && len(rendered) > 0 {
		rendered = append(rendered, "//")
	}
	out := make([]string, 0, len(lines)-h.end+len(rendered))
	out = append(out, rendered...)
	out = append(out, lines[h.end:]...)
	return out
}
