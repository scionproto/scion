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

// header is the copyright block at the top of a file.
type header struct {
	// claims are the first len(claims) lines of the file, in order.
	claims []claim
	// separate appends the blank comment line goheader requires between the
	// claims and the license text.
	separate bool
}

// skipReason is empty when the file is not skipped.
type skipReason string

const (
	skipGenerated   skipReason = "generated file"
	skipNoHeader    skipReason = "no copyright header and no license block"
	skipForeign     skipReason = "unrecognized copyright notice, possibly third-party"
	skipUnknownOrgs skipReason = "copyright held by an organization not in organizations.go"
)

// parseHeader locates the copyright claims in lines. It refuses any notice it does not
// fully recognize: mangling a third-party notice is worse than leaving it outdated.
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
			return nil, skipUnknownOrgs
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

// splitHolders splits "SCION Association, Anapaya Systems" into its holders.
// It reports false unless every holder is one of [organizations].
func splitHolders(text string) ([]string, bool) {
	parts := strings.Split(text, ",")
	holders := make([]string, 0, len(parts))
	for _, part := range parts {
		org, ok := knownOrg(part)
		if !ok {
			return nil, false
		}
		holders = append(holders, org)
	}
	return holders, true
}

// update returns the claim lines of the header with org claiming year,
// or nil when org already claims year or later and nothing needs to change.
// lines is the file the header was parsed from.
//
// A line org holds alone moves to year in place; of several, the newest does.
// A line org shares is left alone, since it states the other holders' year too.
// Without a line of its own, org gets one below the existing claims.
// Either way the claims keep their order, and every other line stays as it was.
func (h *header) update(lines []string, org string, year int) []string {
	alone := -1
	for i, c := range h.claims {
		if !slices.Contains(c.holders, org) {
			continue
		}
		if c.year >= year {
			return nil
		}
		if len(c.holders) == 1 && (alone == -1 || c.year > h.claims[alone].year) {
			alone = i
		}
	}
	claims := slices.Clone(lines[:len(h.claims)])
	if alone == -1 {
		return append(claims, claim{year: year, holders: []string{org}}.String())
	}
	// The holder keeps the spelling the line gave it.
	line := claims[alone]
	m := claimLine.FindStringSubmatchIndex(line)
	claims[alone] = line[:m[2]] + strconv.Itoa(year) + line[m[3]:]
	return claims
}

// render returns lines with the claim block replaced by claims.
func (h *header) render(lines, claims []string) []string {
	out := make([]string, 0, len(claims)+1+len(lines)-len(h.claims))
	out = append(out, claims...)
	if h.separate {
		out = append(out, "//")
	}
	return append(out, lines[len(h.claims):]...)
}
