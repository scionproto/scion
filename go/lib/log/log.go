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

package log

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"
	"github.com/kormat/fmt15" // Allows customization of timestamps and multi-line support
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
)

type Logger log15.Logger
type Handler log15.Handler

var (
	logDir         string
	logLevel       string
	logConsole     string
	logSize        int
	logAge         int
	logFlush       int
	logBuf         *syncBuf
	logFileHandler Handler
	logConsHandler Handler
)

func init() {
	fmt15.TimeFmt = common.TimeFmt
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
			return common.NewBasicError("Log file flags not set", nil)
		}
		err = SetupLogFile(name, logDir, logLevel, logSize, logAge, logFlush)
	}
	return err
}

func SetupLogFile(name string, logDir string, logLevel string, logSize int, logAge int,
	logFlush int) error {

	logLvl, err := log15.LvlFromString(logLevel)
	if err != nil {
		return common.NewBasicError("Unable to parse log.level flag:", err)
	}
	logBuf = newSyncBuf(mkLogfile(name))
	logFileHandler = log15.LvlFilterHandler(logLvl,
		log15.StreamHandler(logBuf, fmt15.Fmt15Format(nil)))
	setHandlers()
	go func() {
		for range time.Tick(time.Duration(logFlush) * time.Second) {
			Flush()
		}
	}()
	return nil
}

func SetupLogConsole(logConsole string) error {
	logLvl, err := log15.LvlFromString(logConsole)
	if err != nil {
		return common.NewBasicError("Unable to parse log.console flag:", err)
	}
	logConsHandler = log15.LvlFilterHandler(logLvl, log15.StreamHandler(os.Stdout,
		fmt15.Fmt15Format(fmt15.ColorMap)))
	setHandlers()
	return nil
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

func AddLogConsFlags() {
	flag.StringVar(&logConsole, "log.console", "crit",
		"Console logging level: debug|info|warn|error|crit")
}

func AddLogFileFlags() {
	flag.StringVar(&logDir, "log.dir", "logs", "Log directory")
	flag.StringVar(&logLevel, "log.level", "debug",
		"File logging level: debug|info|warn|error|crit")
	flag.IntVar(&logSize, "log.size", 50, "Max size of log file in MiB")
	flag.IntVar(&logAge, "log.age", 7, "Max age of log file in days")
	flag.IntVar(&logFlush, "log.flush", 5, "How frequently to flush to the log file, in seconds")
}

func mkLogfile(name string) io.WriteCloser {
	return &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.log", logDir, name),
		MaxSize:  logSize, // MiB
		MaxAge:   logAge,  // days
	}
}

func LogPanicAndExit() {
	if msg := recover(); msg != nil {
		log15.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		Flush()
		os.Exit(255)
	}
}

func Flush() {
	logBuf.Flush()
}

func New(ctx ...interface{}) Logger {
	return log15.New(ctx...)
}

func DiscardHandler() Handler {
	return log15.DiscardHandler()
}

func Root() Logger {
	return log15.Root()
}

func Debug(msg string, ctx ...interface{}) {
	log15.Debug(msg, ctx...)
}

func Info(msg string, ctx ...interface{}) {
	log15.Info(msg, ctx...)
}

func Warn(msg string, ctx ...interface{}) {
	log15.Warn(msg, ctx...)
}

func Error(msg string, ctx ...interface{}) {
	log15.Error(msg, ctx...)
}

func Crit(msg string, ctx ...interface{}) {
	log15.Crit(msg, ctx...)
}

func RandId(idlen int) string {
	return logext.RandId(idlen)
}
