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
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
)

type Lvl log15.Lvl

const (
	LvlCrit  = Lvl(log15.LvlCrit)
	LvlError = Lvl(log15.LvlError)
	LvlWarn  = Lvl(log15.LvlWarn)
	LvlInfo  = Lvl(log15.LvlInfo)
	LvlDebug = Lvl(log15.LvlDebug)

	TsFormat = "2006-01-02 15:04:05.000000+0000"
)

func LvlFromString(lvl string) (Lvl, error) {
	l := strings.ToLower(lvl)
	// Since we also parse python log entries we also have to handle the levels of python.
	switch l {
	case "debug", "dbug":
		return LvlDebug, nil
	case "info":
		return LvlInfo, nil
	case "warn", "warning":
		return LvlWarn, nil
	case "error", "eror":
		return LvlError, nil
	case "crit", "critical":
		return LvlCrit, nil
	default:
		return LvlDebug, fmt.Errorf("Unknown level: %v", lvl)
	}
}

func (l Lvl) String() string {
	return strings.ToUpper(log15.Lvl(l).String())
}

// Logentry is one entry in a log.
// Note that the Entry might be multiple lines if the log entry spanned over multiple lines.
type Logentry struct {
	Timestamp time.Time
	// Element describes the source of this Logentry, e.g. the file name.
	Element string
	Level   Lvl
	Entry   string
}

func (l Logentry) String() string {
	return fmt.Sprintf("%s [%s] %s\n", l.Timestamp.Format(TsFormat), l.Level, l.Entry)
}

// ParseFrom parses log lines from the reader.
//
// 2017-05-16T13:18:16.539536145+0000 [DBUG] Topology loaded topo=
// >  Loc addrs:
// >    127.0.0.65:30066
// >  Interfaces:
// >    IFID: 41 Link: CORE Local: 127.0.0.6:50000 Remote: 127.0.0.7:50000 IA: 1-ff00:0:312 MTU: 1472 BW: 1000
// 2017-05-16T13:18:16.539658666+0000 [INFO] Starting up id=br1-ff00:0:311-1
//
// Lines starting with "> " or a space are assumed to be continuations, i.e.
// they belong with the line(s) above them.
//
// Continuation lines are indented with the given indent.
// The fileName is used for logging.
// The element is put in Logentry.Element.
// Parsed entries are passed to the entryConsumer.
func ParseFrom(reader io.Reader, indent, fileName, element string,
	entryConsumer func(Logentry)) {
	var prevEntry *Logentry
	scanner := bufio.NewScanner(reader)
	lineno := 0
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		if isContinuation(line) {
			// If this is a continuation at the start of the reader, just drop it
			if prevEntry == nil {
				continue
			}
			prevEntry.Entry += fmt.Sprintf("\n%s %s", indent, line)
			continue
		}
		entry := parseInitialEntry(line, fileName, element, lineno)
		if entry == nil {
			continue
		}
		if prevEntry != nil {
			entryConsumer(*prevEntry)
		}
		prevEntry = entry
	}
	if prevEntry != nil {
		entryConsumer(*prevEntry)
	}
}

// parseInitialEntry parses a line with the pattern <TS> [<Level>] <Entry>.
func parseInitialEntry(line, fileName, element string, lineno int) *Logentry {
	tsLen := len(TsFormat)

	if len(line) < tsLen {
		Error(fmt.Sprintf("Short line at %s:%d: '%+v'\n", fileName, lineno, line))
		return nil
	}
	ts, err := time.Parse(TsFormat, line[:tsLen])
	if err != nil {
		Error(fmt.Sprintf("%s:%d: Could not parse timestamp %+v: %+v\n",
			fileName, lineno, line[:tsLen], err))
		return nil
	}
	idx := strings.IndexRune(line[tsLen:min(len(line), tsLen+15)], ']')
	lvl := LvlDebug
	entry := line[tsLen+1:]
	if idx < 0 {
		Error(fmt.Sprintf("%s:%d: Missing log level\n", fileName, lineno))
	} else {
		levelStart := tsLen + 2 // space and [
		levelEnd := tsLen + idx
		lvlS := line[levelStart:levelEnd]
		lvl, err = LvlFromString(lvlS)
		if err != nil {
			Error(fmt.Sprintf("%s:%d: Unknown log level: %v: %v\n", fileName, lineno, lvlS, err))
		}
		entry = line[min(len(line), levelEnd+2):] // ] and space
	}
	return &Logentry{
		Timestamp: ts,
		Element:   element,
		Level:     lvl,
		Entry:     entry,
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
