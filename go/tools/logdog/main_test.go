// Copyright 2019 Anapaya Systems
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

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/logparse"
	"github.com/stretchr/testify/assert"
)

func TestFilters(t *testing.T) {
	tests := map[string]struct {
		Entry   logparse.LogEntry
		Filters Filters
		Keep    assert.BoolAssertionFunc
	}{
		"No filters keeps entry": {
			Entry: logparse.LogEntry{Lines: []string{"foo"}},
			Keep:  assert.True,
		},
		"Discarding filter discards": {
			Entry:   logparse.LogEntry{Lines: []string{"foo"}},
			Filters: []Filter{Contains("bar")},
			Keep:    assert.False,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.Keep(t, test.Filters.Keep(test.Entry))
		})
	}
}

func TestMinLevelFilter(t *testing.T) {
	tests := map[string]struct {
		Entry    logparse.LogEntry
		MinLevel log.Lvl
		Keep     assert.BoolAssertionFunc
	}{
		"Crit entry is kept with Crit min": {
			Entry:    logparse.LogEntry{Level: log.LvlCrit},
			MinLevel: log.LvlCrit,
			Keep:     assert.True,
		},
		"Debug is removed with Info min": {
			Entry:    logparse.LogEntry{Level: log.LvlDebug},
			MinLevel: log.LvlInfo,
			Keep:     assert.False,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := MinLevel(test.MinLevel)
			test.Keep(t, f.Keep(test.Entry))
		})
	}
}

func TestContainsFilter(t *testing.T) {
	tests := map[string]struct {
		Entry logparse.LogEntry
		Check string
		Keep  assert.BoolAssertionFunc
	}{
		"Entry with no lines is filtered": {
			Keep: assert.False,
		},
		"Empty string is always contained": {
			Entry: logparse.LogEntry{Lines: []string{"foo", "bar"}},
			Keep:  assert.True,
		},
		"Entry which matches in first line is kept": {
			Entry: logparse.LogEntry{Lines: []string{"foo tr=112", "bar"}},
			Check: "tr=112",
			Keep:  assert.True,
		},
		"Entry which matches in last line is kept": {
			Entry: logparse.LogEntry{Lines: []string{"foo", "bar", "aa tr=112"}},
			Check: "tr=112",
			Keep:  assert.True,
		},
		"Entry with exact match matches": {
			Entry: logparse.LogEntry{Lines: []string{"foo"}},
			Check: "foo",
			Keep:  assert.True,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := Contains(test.Check)
			test.Keep(t, f.Keep(test.Entry))
		})
	}
}
