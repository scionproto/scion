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

package integration

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/log/logparse"
)

type LogRedirect func(name, pName string, local addr.IA, ep io.ReadCloser)

// StdLog tries to parse any log line from the standard format and logs it with the same log level
// as the original log entry to the log file.
var StdLog LogRedirect = func(name, pName string, local addr.IA, ep io.ReadCloser) {
	defer log.LogPanicAndExit()
	defer ep.Close()
	logparse.ParseFrom(ep, pName, pName, func(e logparse.LogEntry) {
		log.Log(e.Level, fmt.Sprintf("%s@%s: %s", name, local, strings.Join(e.Lines, "\n")))
	})
}

// NonStdLog directly logs any lines as error to the log file
var NonStdLog LogRedirect = func(name, pName string, local addr.IA, ep io.ReadCloser) {
	defer log.LogPanicAndExit()
	defer ep.Close()
	scanner := bufio.NewScanner(ep)
	for scanner.Scan() {
		log.Error(fmt.Sprintf("%s@%s: %s", name, local, scanner.Text()))
	}
}

func replacePattern(pattern string, replacement string, args []string) []string {
	// first copy
	argsCopy := append([]string(nil), args...)
	for i, arg := range argsCopy {
		if strings.Contains(arg, pattern) {
			argsCopy[i] = strings.Replace(arg, pattern, replacement, -1)
		}
	}
	return argsCopy
}
