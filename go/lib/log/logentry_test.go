// Copyright 2018 ETH Zurich
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

package log

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/xtest"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	indent = "<ind>"
)

func TestParseFrom(t *testing.T) {
	defaultTs := mustParse("2018-07-19 14:39:29.489625+0000", t)
	tests := []struct {
		Name    string
		Input   string
		Entries []Logentry
	}{
		{
			Name:  "SingleLineTest",
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt",
			Entries: []Logentry{
				Logentry{
					Timestamp: defaultTs,
					Level:     LvlError,
					Entry:     "Txt",
				},
			},
		},
		{
			Name: "MultilineTest",
			Input: "2018-07-19 14:39:29.489625+0000 [CRIT] (CliSrvExt 2-ff00:0: > ...\n" +
				"> SCIONDPathReplyEntry:",
			Entries: []Logentry{
				Logentry{
					Timestamp: defaultTs,
					Level:     LvlCrit,
					Entry: "(CliSrvExt 2-ff00:0: > ...\n" +
						indent + " > SCIONDPathReplyEntry:",
				},
			},
		},
		{
			Name:  "MissingLevel",
			Input: "2018-07-19 14:39:29.489625+0000 Txt",
			Entries: []Logentry{
				Logentry{
					Timestamp: defaultTs,
					Level:     LvlDebug,
					Entry:     "Txt",
				},
			},
		},
		{
			Name: "MultiEntry",
			Input: "2018-07-19 14:39:29.489625+0000 [ERROR] Txt\n" +
				"2018-07-19 14:39:30.489625+0000 [INFO] Txt2",
			Entries: []Logentry{
				Logentry{
					Timestamp: defaultTs,
					Level:     LvlError,
					Entry:     "Txt",
				},
				Logentry{
					Timestamp: mustParse("2018-07-19 14:39:30.489625+0000", t),
					Level:     LvlInfo,
					Entry:     "Txt2",
				},
			},
		},
	}
	Convey("ParseFrom", t, func() {
		for _, tc := range tests {
			Convey(tc.Name, func() {
				r := strings.NewReader(tc.Input)
				var entries []Logentry
				ParseFrom(r, indent, tc.Name, tc.Name,
					func(e Logentry) { entries = append(entries, e) })
				SoMsg("entries len", len(entries), ShouldEqual, len(tc.Entries))
				for i, e := range entries {
					SoMsg("entry ts", e.Timestamp, ShouldResemble, tc.Entries[i].Timestamp)
					SoMsg("entry element", e.Element, ShouldEqual, tc.Name)
					SoMsg("entry level", e.Level, ShouldEqual, tc.Entries[i].Level)
					SoMsg("entry entry", e.Entry, ShouldResemble, tc.Entries[i].Entry)
				}
			})
		}
	})
}

func mustParse(ts string, t *testing.T) time.Time {
	tts, err := time.Parse(TsFormat, ts)
	xtest.FailOnErr(t, err)
	return tts
}

func TestMain(m *testing.M) {
	l := Root()
	l.SetHandler(DiscardHandler())
	os.Exit(m.Run())
}
