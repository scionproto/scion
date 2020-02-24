// Copyright 2016 ETH Zurich
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

// Read and interleave Python and Go log files as produced by log15/fmt15,
// and Python logging.
// See the documentation for go/lib/log/logparse for the format of the log lines.
//
// Further, the code prefixes all log entries with the processed filename of
// the line was read from, stripped of the path and extension. I.e.
// foo/bar/br1-ff00_0_311-1.log turns into the prefix br1-ff00_0_311-1.
// The prefix is only printed once for blocks coming from the same file. The
// timestamp format of the output is the same as the input format, i.e. ISO8601
// with a space instead of "T".
//
// Limitations:
// - All the logs are kept in memory prior to output. Processing terabytes of
//   logs is thus not recommended.
// - The tool does not care about stdin
// - The tool tries to keep going in the face of errors, but will emit messages
//   to stderr when doing so.

package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/logparse"
)

var (
	version      = flag.Bool("version", false, "Output version information and exit.")
	logLevelFlag = flag.String("level", "DBUG",
		fmt.Sprintf(
			"The minimum (inclusive) log level a line must have to be included in the output,"+
				" any of [%s] (case insensitive)", strings.Join([]string{
				log.LevelDebug.String(),
				log.LevelInfo.String(),
				log.LevelWarn.String(),
				log.LevelError.String(),
				log.LevelCrit.String(),
			}, ",")))
	containsFlag = flag.String("contains", "",
		"A string that must be contained in a log line to be included in the output.")
)

func main() {
	flag.Usage = printUsage
	flag.Parse()
	if *version {
		fmt.Print(env.VersionInfo())
		os.Exit(0)
	}

	f, err := filterFromFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create filters: %s\n", err)
		os.Exit(1)
	}
	maxENameLen := 0
	// Read in all files
	for _, fn := range flag.Args() {
		fileEntries := entriesFromFile(fn, f)
		entries = append(entries, fileEntries...)
		eNameLen := len(fnToEName(fn))
		if eNameLen > maxENameLen {
			maxENameLen = eNameLen
		}
	}
	indent := strings.Repeat(" ", maxENameLen+3)
	fmtL := "[%-" + strconv.Itoa(maxENameLen) + "s] %s"
	// Sort by timestamp and output
	sort.Sort(entries)
	lastelement := ""
	for _, entry := range entries {
		if entry.Element == lastelement {
			fmt.Printf("%s%s", indent, fmtEntry(entry, indent))
		} else {
			lastelement = entry.Element
			fmt.Printf(fmtL, entry.Element, fmtEntry(entry, indent))
		}
	}
}

func filterFromFlags() (Filter, error) {
	var filters Filters
	logLevel, err := log.LevelFromString(*logLevelFlag)
	if err != nil {
		return filters, err
	}
	filters = append(filters, MinLevel(logLevel))
	filters = append(filters, Contains(*containsFlag))
	return filters, nil
}

func fmtEntry(l logparse.LogEntry, indent string) string {
	return fmt.Sprintf("%s [%s] %s\n", l.Timestamp.Format(common.TimeFmt), l.Level,
		strings.Join(l.Lines, "\n"+indent))
}

type LogEntries []logparse.LogEntry

var entries LogEntries

// Implement interface for sort.Sort()
func (e LogEntries) Len() int {
	return len(e)
}

func (e LogEntries) Less(i, j int) bool {
	return e[i].Timestamp.UnixNano() < e[j].Timestamp.UnixNano()
}

func (e LogEntries) Swap(i, j int) { e[i], e[j] = e[j], e[i] }

// Turn a path name like "foo/bar/logs/br1-ff00_0_311-1.log" into "br1-ff00_0_311-1"
// Note that sthis also strips the suffix, no matter its contents, i.e. it will
// strip .log, .DEBUG, .INFO etc., basically anything after (and including) the
// rightmost dot in the basename of the path
func fnToEName(s string) string {
	ext := path.Ext(s)
	return strings.TrimSuffix(path.Base(s), ext)
}

func printUsage() {
	fmt.Printf("Usage: %s <logfile> [logfile ...]\n", os.Args[0])
	flag.PrintDefaults()
}

// entriesFromFile gets all log entries from the file with a given minimum
// level.
func entriesFromFile(fn string, filter Filter) LogEntries {
	var entries LogEntries
	f, err := os.Open(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open file %s: %s\n", fn, err)
		return entries // empty slice
	}
	defer f.Close()
	logparse.ParseFrom(f, fn, fnToEName(fn), func(e logparse.LogEntry) {
		if filter.Keep(e) {
			entries = append(entries, e)
		}
	})
	return entries
}

// Filter filters log entries. If keep returns true an entry is kept, otherwise
// it is dropped.
type Filter interface {
	Keep(logparse.LogEntry) bool
}

// Filters is a list of filters that is applied in order.
type Filters []Filter

// Keep returns whether all filters vote for keeping a line.
func (fs Filters) Keep(e logparse.LogEntry) bool {
	for _, f := range fs {
		if !f.Keep(e) {
			return false
		}
	}
	return true
}

// FilterFunc is a convenience wrapper to create Filters from functions.
type FilterFunc func(logparse.LogEntry) bool

func (f FilterFunc) Keep(e logparse.LogEntry) bool {
	return f(e)
}

// MinLevel returns a filter that checks that an entry has at least level min.
func MinLevel(min log.Level) Filter {
	return FilterFunc(func(e logparse.LogEntry) bool {
		return e.Level <= min
	})
}

// Contains returns a filter that checks that s is contained in the log entry.
func Contains(s string) Filter {
	return FilterFunc(func(e logparse.LogEntry) bool {
		for _, l := range e.Lines {
			if strings.Contains(l, s) {
				return true
			}
		}
		return false
	})
}
