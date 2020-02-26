// Copyright 2018 Anapaya Systems
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

package logparse

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

func TestParseFrom(t *testing.T) {
	defaultTs := mustParse("2018-07-19 14:39:29.489625+0000", t)
	tests := map[string]struct {
		Input   string
		Entries []LogEntry
	}{
		"SingleLineTest": {
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LevelError,
					Lines:     []string{"Txt"},
				},
			},
		},
		"MultilineTest": {
			Input: "2018-07-19 14:39:29.489625+0000 [CRIT] (CliSrvExt 2-ff00:0: > ...\n" +
				"> SCIONDPathReplyEntry:",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LevelCrit,
					Lines:     []string{"(CliSrvExt 2-ff00:0: > ...", "> SCIONDPathReplyEntry:"},
				},
			},
		},
		"MultilineTestSpace": {
			Input: "2018-07-19 14:39:29.489625+0000 [CRIT] (CliSrvExt 2-ff00:0: > ...\n" +
				" SCIONDPathReplyEntry:",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LevelCrit,
					Lines:     []string{"(CliSrvExt 2-ff00:0: > ...", " SCIONDPathReplyEntry:"},
				},
			},
		},
		"MissingLevel": {
			Input: "2018-07-19 14:39:29.489625+0000 Txt",
		},
		"MultiEntry": {
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt\n" +
				"2018-07-19 14:39:30.489625+0000 [INFO] Txt2",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LevelError,
					Lines:     []string{"Txt"},
				},
				{
					Timestamp: mustParse("2018-07-19 14:39:30.489625+0000", t),
					Level:     log.LevelInfo,
					Lines:     []string{"Txt2"},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := strings.NewReader(test.Input)
			var entries []LogEntry
			ParseFrom(r, name, name,
				func(e LogEntry) {
					assert.Equal(t, e.Element, name)
					e.Element = ""
					entries = append(entries, e)
				})
			assert.ElementsMatch(t, test.Entries, entries)
		})
	}
}

func mustParse(ts string, t *testing.T) time.Time {
	tts, err := time.Parse(common.TimeFmt, ts)
	require.NoError(t, err)
	return tts
}

func TestMain(m *testing.M) {
	log.Discard()
	os.Exit(m.Run())
}
