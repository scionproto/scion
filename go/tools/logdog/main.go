// Copyright 2016 ETH Zurich
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

// Read and interleave Python and Go log files as produced by log15/fmt15, zlog
// and Python logging
//
// 2017-05-16T13:18:16.539536145+0000 [DBUG] Topology loaded topo=
// >  Loc addrs:
// >    127.0.0.65:30066
// >  Interfaces:
// >    IFID: 41 Link: CORE Local: 127.0.0.6:50000 Remote: 127.0.0.7:50000 IA: 1-ff00:0:312 MTU: 1472 BW: 1000
// 2017-05-16T13:18:16.539633390+0000 [DBUG] AS Conf loaded conf="CertChainVersion:0 MasterASKey:e856d81efb0878512f78f207bb8aadb3 PropagateTime:5 RegisterPath:true RegisterTime:5"
// 2017-05-16T13:18:16.539658666+0000 [INFO] Starting up id=br1-ff00:0:311-1
//
// Lines starting with "> " or a space are assumed to be continuations, i.e.
// they belong with the line(s) above them.
//
// Further, the code prefixes all log entries with the processed filename of
// the line was read from, stripped of the path and extension. I.e.
// foo/bar/br1-ff00:0:311-1.log turns into the prefix br1-ff00:0:311-1.
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
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const ts_format = "2006-01-02 15:04:05.000000+0000"
const entry_offset = len(ts_format) + 1
const indent_size = 15
const indent = "                 " // 17 spaces

func main() {
	flag.Usage = printUsage
	flag.Parse()
	// Read in all files
	for _, fn := range flag.Args() {
		entries = append(entries, entriesFromFile(fn)...)
	}
	// Sort by timestamp and output
	sort.Sort(entries)
	lastelement := ""
	for _, entry := range entries {
		if entry.Element == lastelement {
			fmt.Printf("%s %s", indent, entry)
		} else {
			lastelement = entry.Element
			fmt.Printf("[%-15s] %s", entry.Element, entry)
		}
	}
}

type Logentry struct {
	Timestamp time.Time
	Element   string
	Entry     string
}

func (l Logentry) String() string {
	return fmt.Sprintf("%s %s\n", l.Timestamp.Format(ts_format), l.Entry)
}

type LogEntries []Logentry

var entries LogEntries

// Implement interface for sort.Sort()
func (e LogEntries) Len() int {
	return len(e)
}

func (e LogEntries) Less(i, j int) bool {
	return e[i].Timestamp.UnixNano() < e[j].Timestamp.UnixNano()
}

func (e LogEntries) Swap(i, j int) { e[i], e[j] = e[j], e[i] }

// Turn a path name like "foo/bar/logs/br1-ff00:0:311-1.log" into "br1-ff00:0:311-1"
// Note that sthis also strips the suffix, no matter its contents, i.e. it will
// strip .log, .DEBUG, .INFO etc., basically anything after (and including) the
// rightmost dot in the basename of the path
// If the name is still longer than indent_size characters, truncate.
func fnToEName(s string) string {
	ext := path.Ext(s)
	name := strings.TrimSuffix(path.Base(s), ext)
	return name[:int64(math.Min(float64(len(name)), indent_size))]
}

func printUsage() {
	fmt.Printf("Usage: %s <logfile> [logfile ...]\n", os.Args[0])
	flag.PrintDefaults()
}

func entriesFromFile(fn string) LogEntries {
	var entries LogEntries
	var ts time.Time
	f, err := os.Open(fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open file %s: %s\n", fn, err)
		return entries // empty slice
	}
	scanner := bufio.NewScanner(f)
	lineno := 0
	for scanner.Scan() {
		lineno += 1
		line := scanner.Text()
		if strings.HasPrefix(line, "> ") || strings.HasPrefix(line, " ") {
			// Continuation
			// If this is a continuation at the start of the file, just drop it
			if len(entries) == 0 {
				continue
			}
			entries[len(entries)-1].Entry += fmt.Sprintf("\n%s %s", indent, line)
			continue
		}
		if len(line) < entry_offset-1 {
			fmt.Fprintf(os.Stderr, "Short line at %s:%d: '%+v'\n", fn, lineno, line)
			continue
		}
		ts, err = time.Parse(ts_format, line[:entry_offset-1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s:%d: Could not parse timestamp %+v: %+v\n",
				fn, lineno, line[:entry_offset-1], err)
			continue
		}
		entries = append(entries, Logentry{
			Timestamp: ts,
			Element:   fnToEName(fn),
			Entry:     line[entry_offset:],
		})
	}
	return entries
}
