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

package liblog

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	log "github.com/inconshreveable/log15"
	"github.com/kormat/fmt15"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logDir = flag.String("log.dir", "logs", "Log directory")
var logLevel = flag.String("log.level", "debug", "Logging level")
var logConsole = flag.String("log.console", "crit", "Console logging level")
var logSize = flag.Int("log.size", 50, "Max size of log file in MiB")
var logAge = flag.Int("log.age", 7, "Max age of log file in days")

var logBuf *bufio.Writer

func init() {
	os.Setenv("TZ", "UTC")
	fmt15.TimeFmt = "2006-01-02T15:04:05.000000000-0700"
}

func Setup(name string) {
	// logLvl, consLvl := parseLvls()
	//var handlers []log.Handler
	logFile, err := os.OpenFile(fmt.Sprintf("%s/%s.log", *logDir, name),
		os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	logBuf = bufio.NewWriter(logFile)
	//handler := log.LvlFilterHandler(logLvl, log.StreamHandler(logBuf, fmt15.Fmt15Format(nil)))
	handler := log.StreamHandler(logBuf, fmt15.Fmt15Format(nil))
	/*
				lvls := []log.Lvl{log.LvlCrit, log.LvlError, log.LvlWarn, log.LvlInfo, log.LvlDebug}
				for _, lvl := range lvls[:logLvl+1] {
					handlers = append(handlers, mkFilterCallerStreamFile(lvl, name))
				}
			stdoutH := log.StreamHandler(os.Stdout, fmt15.Fmt15Format(fmt15.ColorMap))
			handlers = append(handlers, mkFilterCaller(consLvl, stdoutH))
		handler := log.CallerFileHandler(log.MultiHandler(handlers...))
	*/
	log.Root().SetHandler(handler)
}

func parseLvls() (log.Lvl, log.Lvl) {
	logLvl, err := log.LvlFromString(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Level flag: %v", err)
		os.Exit(1)
	}
	consLvl, err := log.LvlFromString(*logConsole)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Console flag: %v", err)
		os.Exit(1)
	}
	return logLvl, consLvl
}

func mkStreamHandler(lvl log.Lvl, name string) log.Handler {
	out := &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.%s", *logDir, name, lvlName(lvl)),
		MaxSize:  50, // MiB
		MaxAge:   7,  // days
	}
	return log.StreamHandler(out, fmt15.Fmt15Format(nil))
}

func mkFilterCaller(lvl log.Lvl, out log.Handler) log.Handler {
	return log.LvlFilterHandler(lvl, out)
}

func mkFilterCallerStreamFile(lvl log.Lvl, name string) log.Handler {
	out := mkStreamHandler(lvl, name)
	return mkFilterCaller(lvl, out)
}

func lvlName(lvl log.Lvl) string {
	switch lvl {
	case log.LvlCrit:
		return "CRITICAL"
	case log.LvlError:
		return "ERROR"
	case log.LvlWarn:
		return "WARNING"
	case log.LvlInfo:
		return "INFO"
	case log.LvlDebug:
		return "DEBUG"
	}
	return "UNKNOWN"
}

func PanicLog() {
	if msg := recover(); msg != nil {
		log.Crit("Panic", "msg", msg, "stack", log.CustomString(debug.Stack()))
	}
}

func Flush() {
	logBuf.Flush()
}
