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

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/xtest"
)

func TestParseFrom(t *testing.T) {
	defaultTs := mustParse("2018-07-19 14:39:29.489625+0000", t)
	tests := []struct {
		Name    string
		Input   string
		Entries []LogEntry
	}{
		{
			Name:  "SingleLineTest",
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LvlError,
					Lines:     []string{"Txt"},
				},
			},
		},
		{
			Name: "MultilineTest>",
			Input: "2018-07-19 14:39:29.489625+0000 [CRIT] (CliSrvExt 2-ff00:0: > ...\n" +
				"> SCIONDPathReplyEntry:",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LvlCrit,
					Lines:     []string{"(CliSrvExt 2-ff00:0: > ...", "> SCIONDPathReplyEntry:"},
				},
			},
		},
		{
			Name: "MultilineTestSpace",
			Input: "2018-07-19 14:39:29.489625+0000 [CRIT] (CliSrvExt 2-ff00:0: > ...\n" +
				" SCIONDPathReplyEntry:",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LvlCrit,
					Lines:     []string{"(CliSrvExt 2-ff00:0: > ...", " SCIONDPathReplyEntry:"},
				},
			},
		},
		{
			Name:  "MissingLevel",
			Input: "2018-07-19 14:39:29.489625+0000 Txt",
		},
		{
			Name: "MultiEntry",
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt\n" +
				"2018-07-19 14:39:30.489625+0000 [INFO] Txt2",
			Entries: []LogEntry{
				{
					Timestamp: defaultTs,
					Level:     log.LvlError,
					Lines:     []string{"Txt"},
				},
				{
					Timestamp: mustParse("2018-07-19 14:39:30.489625+0000", t),
					Level:     log.LvlInfo,
					Lines:     []string{"Txt2"},
				},
			},
		},
	}
	Convey("ParseFrom", t, func() {
		for _, tc := range tests {
			Convey(tc.Name, func() {
				r := strings.NewReader(tc.Input)
				var entries []LogEntry
				ParseFrom(r, tc.Name, tc.Name,
					func(e LogEntry) { entries = append(entries, e) })
				SoMsg("entries len", len(entries), ShouldEqual, len(tc.Entries))
				for i, e := range entries {
					SoMsg("entry ts", e.Timestamp, ShouldResemble, tc.Entries[i].Timestamp)
					SoMsg("entry element", e.Element, ShouldEqual, tc.Name)
					SoMsg("entry level", e.Level, ShouldEqual, tc.Entries[i].Level)
					SoMsg("entry entry", e.Lines, ShouldResemble, tc.Entries[i].Lines)
				}
			})
		}
	})
}

func mustParse(ts string, t *testing.T) time.Time {
	tts, err := time.Parse(common.TimeFmt, ts)
	xtest.FailOnErr(t, err)
	return tts
}

func TestMain(m *testing.M) {
	l := log.Root()
	l.SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}
