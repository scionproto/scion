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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testResolver returns a resolver independent of affiliations.json.
func testResolver(t *testing.T) *Resolver {
	t.Helper()
	cfg := &Config{
		Organizations: []string{"SCION Association", "Anapaya Systems", "ETH Zurich"},
		Domains: map[string]string{
			"anapaya.net": "Anapaya Systems",
			"scion.org":   "SCION Association",
			"inf.ethz.ch": "ETH Zurich",
		},
		Contributors: []Contributor{
			{
				Name:         "Mover",
				Emails:       []string{"mover@example.com"},
				Affiliations: []string{"SCION Association", "ETH Zurich"},
			},
		},
		IgnoreEmails: []string{"bot@example.com"},
	}
	require.NoError(t, cfg.validate())
	require.NoError(t, cfg.ApplyDates(Dates{{
		Name: "Mover",
		Affiliations: []Affiliation{
			{Org: "SCION Association", From: "2023-01-01"},
			{Org: "ETH Zurich", From: "2018-01-01", Until: "2022-12-31"},
		},
	}}))
	return cfg.NewResolver()
}

const licenseBlock = `//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main
`

// licenseAndSPDX carries the tag in a comment of its own below the header, the
// layout private/underlay/ebpf uses.
const licenseAndSPDX = `//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// SPDX-License-Identifier: Apache-2.0

package main
`

// TestReasons checks that every claim line the update moved cites the
// contribution behind it, and that untouched lines cite nothing.
func TestReasons(t *testing.T) {
	anapaya := attribution{year: 2025, email: "who@anapaya.net",
		source: source{date: "2025-03-04", commit: "a1b2c3d"}}
	scion := attribution{year: 2025, email: "who@scion.org"}
	eth := attribution{year: 2019, email: "who@inf.ethz.ch",
		source: source{date: "2019-07-08", commit: "9f8e7d6"}}

	old := []claim{
		{year: 2020, holders: []string{"Anapaya Systems"}},
		{year: 2019, holders: []string{"ETH Zurich"}},
	}
	updated := []claim{
		{year: 2025, holders: []string{"Anapaya Systems", "SCION Association"}},
		{year: 2019, holders: []string{"ETH Zurich"}},
	}
	attr := map[string]attribution{
		"Anapaya Systems":   anapaya,
		"SCION Association": scion,
		"ETH Zurich":        eth,
	}

	require.Equal(t, map[string]string{
		"// Copyright 2025 Anapaya Systems, SCION Association": "Anapaya Systems: " +
			"who@anapaya.net, 2025-03-04 a1b2c3d; " +
			"SCION Association: who@scion.org, uncommitted",
	}, reasons(old, updated, attr),
		"the ETH line still claims the year it already claimed")
}

// TestReasonsSingleHolder checks that a line held by one organization cites the
// contribution without repeating the holder's name.
func TestReasonsSingleHolder(t *testing.T) {
	updated := []claim{{year: 2025, holders: []string{"SCION Association"}}}
	attr := map[string]attribution{"SCION Association": {
		year: 2025, email: "who@scion.org",
		source: source{date: "2025-03-04", commit: "a1b2c3d"},
	}}
	require.Equal(t, map[string]string{
		"// Copyright 2025 SCION Association": "who@scion.org, 2025-03-04 a1b2c3d",
	}, reasons(nil, updated, attr))
}

func TestParseHeaderClaims(t *testing.T) {
	testCases := map[string]struct {
		file   string
		claims []claim
		end    int
	}{
		"single holder": {
			file:   "// Copyright 2020 Anapaya Systems\n" + licenseBlock,
			claims: []claim{{year: 2020, holders: []string{"Anapaya Systems"}}},
			end:    1,
		},
		"one per line": {
			file: "// Copyright 2026 SCION Association\n" +
				"// Copyright 2020 Anapaya Systems\n" + licenseBlock,
			claims: []claim{
				{year: 2026, holders: []string{"SCION Association"}},
				{year: 2020, holders: []string{"Anapaya Systems"}},
			},
			end: 2,
		},
		"holders sharing a line": {
			file: "// Copyright 2026 SCION Association, Anapaya Systems\n" + licenseBlock,
			claims: []claim{
				{year: 2026, holders: []string{"SCION Association", "Anapaya Systems"}},
			},
			end: 1,
		},
		"spdx tag below the header": {
			file:   "// Copyright 2025 SCION Association\n" + licenseAndSPDX,
			claims: []claim{{year: 2025, holders: []string{"SCION Association"}}},
			end:    1,
		},
		"license block without a notice": {
			file:   licenseBlock,
			claims: nil,
			end:    0,
		},
	}
	r := testResolver(t)
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			lines, _ := splitLines(tc.file)
			hdr, reason := parseHeader(lines, r)
			require.Empty(t, string(reason))
			assert.Equal(t, tc.claims, hdr.claims)
			assert.Equal(t, tc.end, hdr.end, "end")
		})
	}
}

// TestParseHeaderSkips checks that a file whose notice is not fully recognized
// is left alone. Each case is the shape of a real third-party header in this
// repository.
func TestParseHeaderSkips(t *testing.T) {
	testCases := map[string]struct {
		file   string
		reason skipReason
	}{
		"generated": {
			file:   "// Code generated by MockGen. DO NOT EDIT.\n// Source: whatever\n",
			reason: skipGenerated,
		},
		"generated below a package comment": {
			file: "// Package api provides things.\n//\n" +
				"// Code generated by oapi-codegen version v1 DO NOT EDIT.\n",
			reason: skipGenerated,
		},
		"third-party notice above an spdx line": {
			file: "// Copyright (c) Tailscale Inc & AUTHORS\n" +
				"// SPDX-License-Identifier: BSD-3-Clause\n\npackage stun\n",
			reason: skipForeign,
		},
		"third-party notice under an spdx line": {
			file: "// SPDX-License-Identifier: BSD-3-Clause\n//\n" +
				"// Copyright (c) 2016 Grant Ayers\n" + licenseBlock,
			reason: skipForeign,
		},
		// Claims have to lead the header. A tag above them is not read as a
		// prefix, so the notice below it looks like someone else's.
		"our own notice under an spdx line": {
			file: "// SPDX-License-Identifier: Apache-2.0\n//\n" +
				"// Copyright 2025 SCION Association\n" + licenseBlock,
			reason: skipForeign,
		},
		"third-party holder in our own format": {
			file:   "// Copyright 2013 The Prometheus Authors\n" + licenseBlock,
			reason: skipUnknownOrgs,
		},
		"third-party MIT notice": {
			file:   "// MIT License\n//\n// Copyright (c) 2017 Ben Toews.\n//\n",
			reason: skipForeign,
		},
		"misspaced notice": {
			file:   "//  Copyright 2020 Smallstep Labs, Inc.\n" + licenseBlock,
			reason: skipForeign,
		},
		"unknown organization": {
			file:   "// Copyright 2015 Some Other Corp\n" + licenseBlock,
			reason: skipUnknownOrgs,
		},
		"one unknown holder among known ones": {
			file:   "// Copyright 2015 SCION Association, Some Other Corp\n" + licenseBlock,
			reason: skipUnknownOrgs,
		},
		"foreign notice below ours": {
			file: "// Copyright 2020 Anapaya Systems\n" +
				"// Portions copyright 2011 The Go Authors.\n" + licenseBlock,
			reason: skipForeign,
		},
		"notice below the package clause": {
			file:   "package main\n\n// Copyright 2020 Anapaya Systems\n",
			reason: skipNoHeader,
		},
		"no header at all": {
			file:   "package main\n\nfunc main() {}\n",
			reason: skipNoHeader,
		},
	}
	r := testResolver(t)
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			lines, _ := splitLines(tc.file)
			hdr, reason := parseHeader(lines, r)
			assert.Nil(t, hdr)
			assert.Equal(t, tc.reason, reason)
		})
	}
}

func TestUpdate(t *testing.T) {
	testCases := map[string]struct {
		before        []string
		contributions map[string]int
		after         []string
	}{
		"a new organization goes on top": {
			before:        []string{"// Copyright 2020 Anapaya Systems"},
			contributions: map[string]int{"SCION Association": 2026},
			after: []string{
				"// Copyright 2026 SCION Association",
				"// Copyright 2020 Anapaya Systems",
			},
		},
		"an existing organization moves forward": {
			before:        []string{"// Copyright 2020 Anapaya Systems"},
			contributions: map[string]int{"Anapaya Systems": 2022},
			after:         []string{"// Copyright 2022 Anapaya Systems"},
		},
		"a year is never moved back": {
			before:        []string{"// Copyright 2026 SCION Association"},
			contributions: map[string]int{"SCION Association": 2020},
			after:         []string{"// Copyright 2026 SCION Association"},
		},
		"an unseen holder is never dropped": {
			before: []string{
				"// Copyright 2021 ETH Zurich",
				"// Copyright 2020 Anapaya Systems",
			},
			contributions: map[string]int{"SCION Association": 2026},
			after: []string{
				"// Copyright 2026 SCION Association",
				"// Copyright 2021 ETH Zurich",
				"// Copyright 2020 Anapaya Systems",
			},
		},
		"a shared line stays put when nothing moves": {
			before:        []string{"// Copyright 2026 SCION Association, Anapaya Systems"},
			contributions: map[string]int{"SCION Association": 2026, "Anapaya Systems": 2024},
			after:         []string{"// Copyright 2026 SCION Association, Anapaya Systems"},
		},
		"a shared line splits when one holder moves": {
			before:        []string{"// Copyright 2024 SCION Association, Anapaya Systems"},
			contributions: map[string]int{"SCION Association": 2026},
			after: []string{
				"// Copyright 2026 SCION Association",
				"// Copyright 2024 Anapaya Systems",
			},
		},
		"a mover joins the line for its year": {
			before: []string{
				"// Copyright 2026 ETH Zurich",
				"// Copyright 2024 SCION Association, Anapaya Systems",
			},
			contributions: map[string]int{"SCION Association": 2026},
			after: []string{
				"// Copyright 2026 ETH Zurich, SCION Association",
				"// Copyright 2024 Anapaya Systems",
			},
		},
		"several new organizations arrive at once": {
			before: []string{"// Copyright 2019 Anapaya Systems"},
			contributions: map[string]int{
				"SCION Association": 2026,
				"ETH Zurich":        2021,
				"Anapaya Systems":   2019,
			},
			after: []string{
				"// Copyright 2026 SCION Association",
				"// Copyright 2021 ETH Zurich",
				"// Copyright 2019 Anapaya Systems",
			},
		},
		"nothing to do": {
			before:        []string{"// Copyright 2020 Anapaya Systems"},
			contributions: map[string]int{"Anapaya Systems": 2020},
			after:         []string{"// Copyright 2020 Anapaya Systems"},
		},
	}
	r := testResolver(t)
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			file := strings.Join(tc.before, "\n") + "\n" + licenseBlock
			lines, _ := splitLines(file)
			hdr, reason := parseHeader(lines, r)
			require.Empty(t, string(reason))
			assert.Equal(t, tc.after, renderClaims(hdr.update(tc.contributions)))
		})
	}
}

// TestRender checks that the rewrite touches nothing outside the claim block.
func TestRender(t *testing.T) {
	testCases := map[string]struct {
		before        string
		contributions map[string]int
		after         string
	}{
		"claims replaced in place": {
			before: "// Copyright 2020 Anapaya Systems\n" + licenseBlock,
			contributions: map[string]int{
				"SCION Association": 2026,
				"Anapaya Systems":   2022,
			},
			after: "// Copyright 2026 SCION Association\n" +
				"// Copyright 2022 Anapaya Systems\n" + licenseBlock,
		},
		"spdx tag below the header preserved": {
			before:        "// Copyright 2025 SCION Association\n" + licenseAndSPDX,
			contributions: map[string]int{"SCION Association": 2026},
			after:         "// Copyright 2026 SCION Association\n" + licenseAndSPDX,
		},
		"claims inserted above a bare license": {
			before:        licenseBlock,
			contributions: map[string]int{"SCION Association": 2026},
			after:         "// Copyright 2026 SCION Association\n" + licenseBlock,
		},
	}
	r := testResolver(t)
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			lines, eol := splitLines(tc.before)
			hdr, reason := parseHeader(lines, r)
			require.Empty(t, string(reason))
			out := hdr.render(lines, hdr.update(tc.contributions))
			assert.Equal(t, tc.after, strings.Join(out, eol))
		})
	}
}

func TestRenderKeepsCRLF(t *testing.T) {
	before := strings.ReplaceAll("// Copyright 2020 Anapaya Systems\n"+licenseBlock, "\n", "\r\n")
	lines, eol := splitLines(before)
	require.Equal(t, "\r\n", eol)
	hdr, reason := parseHeader(lines, testResolver(t))
	require.Empty(t, string(reason))
	out := strings.Join(hdr.render(lines, hdr.update(map[string]int{"ETH Zurich": 2026})), eol)
	assert.Equal(t, "// Copyright 2026 ETH Zurich\r\n"+before, out)
}
