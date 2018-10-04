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
	"flag"

	"github.com/scionproto/scion/go/lib/common"
)

var (
	logDir     string
	logLevel   string
	logConsole string
	logSize    int
	logAge     int
	logFlush   int
)

const (
	DefaultConsoleLevel     = "crit"
	DefaultFileLevel        = "debug"
	DefaultFileSizeMiB      = 50
	DefaultFileMaxAgeDays   = 7
	DefaultFileFlushSeconds = 5
)

func AddLogConsFlags() {
	flag.StringVar(&logConsole, "log.console", DefaultConsoleLevel,
		"Console logging level: trace|debug|info|warn|error|crit")
}

func AddLogFileFlags() {
	flag.StringVar(&logDir, "log.dir", "logs", "Log directory")
	flag.StringVar(&logLevel, "log.level", DefaultFileLevel,
		"File logging level: trace|debug|info|warn|error|crit")
	flag.IntVar(&logSize, "log.size", DefaultFileSizeMiB, "Max size of log file in MiB")
	flag.IntVar(&logAge, "log.age", DefaultFileMaxAgeDays, "Max age of log file in days")
	flag.IntVar(&logFlush, "log.flush", DefaultFileFlushSeconds,
		"How frequently to flush to the log file, in seconds")
}

func SetupFromFlags(name string) error {
	var err error
	if logConsole != "" {
		err = SetupLogConsole(logConsole)
		if err != nil {
			return err
		}
	}
	// if name passed, the caller wants to setup a log file
	if name != "" {
		if logDir == "" {
			return common.NewBasicError("Log dir flag not set", nil)
		}
		err = SetupLogFile(name, logDir, logLevel, logSize, logAge, logFlush)
	}
	return err
}
