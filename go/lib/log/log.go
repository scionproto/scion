// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	// Allows customization of timestamps and multi-line support
	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
)

func init() {
	fmt15.TimeFmt = common.TimeFmt
}

var logBuf *syncBuf

var (
	logFileHandler Handler
	logConsHandler Handler
)

// SetupLogFile initializes a file for logging. The path is logDir/name.log if
// name doesn't already contain the .log extension, or logDir/name otherwise.
// logLevel can be one of trace, debug, info, warn, error, and crit and states
// the minimum level of logging events that get written to the file. logSize is
// the maximum size, in MiB, until the log rotates. logAge is the maximum
// number of days to retain old log files. logBackups is the maximum number of
// old log files to retain. If logFlush > 0, logging output is
// buffered, and flushed every logFlush seconds.  If logFlush < 0: logging
// output is buffered, but must be manually flushed by calling Flush(). If
// logFlush = 0 logging output is unbuffered and Flush() is a no-op.
func SetupLogFile(name string, logDir string, logLevel string, logSize int, logAge int,
	logBackups int, logFlush int) error {

	logLvl, err := log15.LvlFromString(changeTraceToDebug(logLevel))
	if err != nil {
		return common.NewBasicError("Unable to parse log.level flag:", err)
	}

	// Strip .log extension s.t. config files can contain the exact filename
	// while not breaking existing behavior for apps that don't contain the
	// extension.
	name = strings.TrimSuffix(name, ".log")
	var fileLogger io.WriteCloser
	fileLogger = &lumberjack.Logger{
		Filename:   fmt.Sprintf("%s/%s.log", logDir, name),
		MaxSize:    logSize, // MiB
		MaxAge:     logAge,  // days
		MaxBackups: logBackups,
	}

	if logFlush != 0 {
		logBuf = newSyncBuf(fileLogger)
		fileLogger = logBuf
	}

	logFileHandler = log15.LvlFilterHandler(logLvl,
		log15.StreamHandler(fileLogger, fmt15.Fmt15Format(nil)))
	if logLevel != LvlTraceStr {
		// Discard trace messages
		logFileHandler = FilterTraceHandler(logFileHandler)
	}
	setHandlers()

	if logFlush > 0 {
		go func() {
			defer LogPanicAndExit()
			for range time.Tick(time.Duration(logFlush) * time.Second) {
				Flush()
			}
		}()
	}
	return nil
}

// SetupLogConsole sets up logging on default stderr. logLevel can be one of
// trace, debug, info, warn, error, and crit, and states the minimum level of
// logging events that gets printed to the console.
func SetupLogConsole(logLevel string) error {
	lvl, err := log15.LvlFromString(changeTraceToDebug(logLevel))
	if err != nil {
		return common.NewBasicError("Unable to parse log.console flag:", err)
	}
	var cMap map[log15.Lvl]int
	if isatty.IsTerminal(os.Stderr.Fd()) {
		cMap = fmt15.ColorMap
	}
	logConsHandler = log15.LvlFilterHandler(lvl,
		log15.StreamHandler(os.Stderr, fmt15.Fmt15Format(cMap)))
	if logLevel != LvlTraceStr {
		// Discard trace messages
		logConsHandler = FilterTraceHandler(logConsHandler)
	}
	setHandlers()
	return nil
}

func changeTraceToDebug(logLevel string) string {
	if logLevel == LvlTraceStr {
		return "debug"
	}
	return logLevel
}

func setHandlers() {
	var handler log15.Handler
	switch {
	case logFileHandler != nil && logConsHandler != nil:
		handler = log15.MultiHandler(logFileHandler, logConsHandler)
	case logFileHandler != nil: // logConsHandler == nil
		handler = logFileHandler
	case logConsHandler != nil: // logFileHandler == nil
		handler = logConsHandler
	}
	log15.Root().SetHandler(handler)
}

func LogPanicAndExit() {
	if msg := recover(); msg != nil {
		log15.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		log15.Crit("=====================> Service panicked!")
		Flush()
		os.Exit(255)
	}
}

func Flush() {
	if logBuf != nil {
		logBuf.Flush()
	}
}
