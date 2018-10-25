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
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

var (
	lineRegex = regexp.MustCompile(` \[(\w+)\] (.+)`)
)

// LogEntry is one entry in a log.
type LogEntry struct {
	Timestamp time.Time
	// Element describes the source of this LogEntry, e.g. the file name.
	Element string
	Level   log.Lvl
	Lines   []string
}

func (l LogEntry) String() string {
	return fmt.Sprintf("%s [%s] %s\n", l.Timestamp.Format(common.TimeFmt), l.Level, l.Lines)
}

// ParseFrom parses log lines from the reader.
//
// 2017-05-16T13:18:16.539536145+0000 [DBUG] Topology loaded topo=
// >  Loc addrs:
// >    127.0.0.65:30066
// >  Interfaces:
// >    IFID: 41 Link: CORE Local: 127.0.0.6:50000 Remote: 127.0.0.7:50000 IA: 1-ff00:0:312
// 2017-05-16T13:18:16.539658666+0000 [INFO] Starting up id=br1-ff00:0:311-1
//
// Lines starting with "> " or a space are assumed to be continuations, i.e.
// they belong with the line(s) above them.
//
// The fileName is used for logging.
// The element is put in LogEntry.Element.
// Parsed entries are passed to the entryConsumer.
func ParseFrom(reader io.Reader, fileName, element string, entryConsumer func(LogEntry)) {
	var prevEntry *LogEntry
	scanner := bufio.NewScanner(reader)
	for lineno := 1; scanner.Scan(); lineno++ {
		line := scanner.Text()
		if isContinuation(line) {
			// If this is a continuation at the start of the reader, just drop it
			if prevEntry == nil {
				continue
			}
			prevEntry.Lines = append(prevEntry.Lines, line)
			continue
		}
		if prevEntry != nil {
			entryConsumer(*prevEntry)
		}
		prevEntry = parseInitialEntry(line, fileName, element, lineno)
	}
	if prevEntry != nil {
		entryConsumer(*prevEntry)
	}
}

// parseInitialEntry parses a line with the pattern <TS> [<Level>] <Entry>.
func parseInitialEntry(line, fileName, element string, lineno int) *LogEntry {
	tsLen := len(common.TimeFmt)

	if len(line) < tsLen {
		log.Error(fmt.Sprintf("Short line at %s:%d: '%+v'", fileName, lineno, line))
		return nil
	}
	ts, err := time.Parse(common.TimeFmt, line[:tsLen])
	if err != nil {
		log.Error(fmt.Sprintf("%s:%d: Could not parse timestamp %+v: %+v",
			fileName, lineno, line[:tsLen], err))
		return nil
	}
	matches := lineRegex.FindStringSubmatch(line[tsLen:])
	if matches == nil || len(matches) < 3 {
		log.Error(fmt.Sprintf("Line %s:%d does not match regexep: %s",
			fileName, lineno, lineRegex))
		return nil
	}
	lvl, err := log.LvlFromString(matches[1])
	if err != nil {
		log.Error(fmt.Sprintf("%s:%d: Unknown log level: %v", fileName, lineno, err))
	}
	return &LogEntry{
		Timestamp: ts,
		Element:   element,
		Level:     lvl,
		Lines:     []string{matches[2]},
	}
}

func isContinuation(line string) bool {
	return strings.HasPrefix(line, "> ") || strings.HasPrefix(line, " ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
