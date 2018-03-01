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
	"github.com/kormat/fmt15" // Allows customization of timestamps and multi-line support
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
)

type Logger log15.Logger

var logDir string
var logLevel string
var logConsole string
var logSize int
var logAge int
var logFlush int

var logBuf *syncBuf

func init() {
	fmt15.TimeFmt = common.TimeFmt
}

func Setup(name string) {
	logLvl, consLvl := parseLvls()
	logBuf = newSyncBuf(mkLogfile(name))
	handler := log15.MultiHandler(
		log15.LvlFilterHandler(logLvl, log15.StreamHandler(logBuf, fmt15.Fmt15Format(nil))),
		log15.LvlFilterHandler(consLvl, log15.StreamHandler(os.Stdout,
			fmt15.Fmt15Format(fmt15.ColorMap))),
	)
	log15.Root().SetHandler(handler)
	go func() {
		for range time.Tick(time.Duration(logFlush) * time.Second) {
			Flush()
		}
	}()
}

func AddDefaultLogFlags() {
	flag.StringVar(&logDir, "log.dir", "logs", "Log directory")
	flag.StringVar(&logLevel, "log.level", "debug", "Logging level")
	flag.StringVar(&logConsole, "log.console", "crit", "Console logging level")
	flag.IntVar(&logSize, "log.size", 50, "Max size of log file in MiB")
	flag.IntVar(&logAge, "log.age", 7, "Max age of log file in days")
	flag.IntVar(&logFlush, "log.flush", 5, "How frequently to flush to the log file, in seconds")
}

func parseLvls() (log15.Lvl, log15.Lvl) {
	logLvl, err := log15.LvlFromString(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Level flag: %v", err)
		os.Exit(1)
	}
	consLvl, err := log15.LvlFromString(logConsole)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Console flag: %v", err)
		os.Exit(1)
	}
	return logLvl, consLvl
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

func DiscardHandler() log15.Handler {
	return log15.DiscardHandler()
}

func Root() Logger {
	return log15.Root()
}

func Debug(msg string, ctx ...interface{}) {
	log15.Debug(msg, ctx)
}

func Info(msg string, ctx ...interface{}) {
	log15.Info(msg, ctx)
}

func Warn(msg string, ctx ...interface{}) {
	log15.Warn(msg, ctx)
}

func Error(msg string, ctx ...interface{}) {
	log15.Error(msg, ctx)
}

func Crit(msg string, ctx ...interface{}) {
	log15.Crit(msg, ctx)
}
