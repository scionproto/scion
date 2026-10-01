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
	"fmt"
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

type header struct {
	claims []claim
	// separate records whether a new claim needs the blank
	// comment line required by goheader before the license text.
	separate bool
}

// skipReason is empty when the file is not skipped.
type skipReason string

const (
	skipGenerated skipReason = "generated file"
	skipNoHeader  skipReason = "no copyright header and no license block"
	skipForeign   skipReason = "unrecognized copyright notice, possibly third-party"
)

// parseHeader rejects unrecognized notices to avoid changing third-party text.
func parseHeader(lines []string) (*header, skipReason) {
	// Only the leading run of "//" lines can hold a notice.
	// Code below can mention copyright in a string or a comment of its own.
	block := 0
	for block < len(lines) && strings.HasPrefix(lines[block], "//") {
		if generatedMarker.MatchString(strings.TrimSpace(lines[block])) {
			return nil, skipGenerated
		}
		block++
	}

	var claims []claim
	for len(claims) < block {
		m := claimLine.FindStringSubmatch(lines[len(claims)])
		if m == nil {
			break
		}
		year, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, skipForeign
		}
		holders, ok := splitHolders(m[2])
		if !ok {
			return nil, skipForeign
		}
		claims = append(claims, claim{year: year, holders: holders})
	}

	// Copyright mentioned outside the parsed claims belongs to someone else.
	if slices.ContainsFunc(lines[len(claims):block], mentionsCopyright) {
		return nil, skipForeign
	}

	if len(claims) == 0 {
		// A missing license is not invented here. goheader flags it.
		for _, line := range lines[:block] {
			if strings.HasPrefix(line, licenseMarker) {
				return &header{separate: strings.TrimSpace(lines[0]) != "//"}, ""
			}
		}
		return nil, skipNoHeader
	}
	return &header{claims: claims}, ""
}

func mentionsCopyright(line string) bool {
	return strings.Contains(line, "Copyright") || strings.Contains(line, "copyright")
}

func splitHolders(text string) ([]string, bool) {
	parts := strings.Split(text, ",")
	holders := make([]string, 0, len(parts))
	for _, part := range parts {
		holder := strings.TrimSpace(part)
		if holder == "" {
			return nil, false
		}
		holders = append(holders, holder)
	}
	return holders, true
}

// update returns nil when org already claims year or later.
//
// Otherwise, org's newest claim moves to year and org is removed from its
// older claims. A shared line splits so that other holders retain their year.
// A new claim goes below the existing claims. Claim order and unrelated lines remain.
func (h *header) update(lines []string, org string, year int) []string {
	newest := -1
	for i, c := range h.claims {
		if !slices.Contains(c.holders, org) {
			continue
		}
		if c.year >= year {
			return nil
		}
		if newest == -1 || c.year > h.claims[newest].year {
			newest = i
		}
	}
	if newest == -1 {
		claims := slices.Clone(lines[:len(h.claims)])
		return append(claims, claim{year: year, holders: []string{org}}.String())
	}
	claims := make([]string, 0, len(h.claims)+2)
	for i, c := range h.claims {
		at := slices.Index(c.holders, org)
		switch {
		case at == -1:
			claims = append(claims, lines[i])
		case i == newest && len(c.holders) == 1:
			m := claimLine.FindStringSubmatchIndex(lines[i])
			claims = append(claims, lines[i][:m[2]]+strconv.Itoa(year)+lines[i][m[3]:])
		case i == newest:
			for _, part := range []claim{
				{year: c.year, holders: c.holders[:at]},
				{year: year, holders: []string{org}},
				{year: c.year, holders: c.holders[at+1:]},
			} {
				if len(part.holders) > 0 {
					claims = append(claims, part.String())
				}
			}
		case len(c.holders) == 1:
			// An older line of org's own goes.
		default:
			others := slices.Delete(slices.Clone(c.holders), at, at+1)
			claims = append(claims, claim{year: c.year, holders: others}.String())
		}
	}
	return claims
}

func (h *header) render(lines, claims []string) []string {
	out := make([]string, 0, len(claims)+1+len(lines)-len(h.claims))
	out = append(out, claims...)
	if h.separate {
		out = append(out, "//")
	}
	return append(out, lines[len(h.claims):]...)
}
