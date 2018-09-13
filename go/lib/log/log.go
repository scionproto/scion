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
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"
	// Allows customization of timestamps and multi-line support
	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
)

type Lvl log15.Lvl

const (
	LvlCrit  = Lvl(log15.LvlCrit)
	LvlError = Lvl(log15.LvlError)
	LvlWarn  = Lvl(log15.LvlWarn)
	LvlInfo  = Lvl(log15.LvlInfo)
	LvlDebug = Lvl(log15.LvlDebug)
)

func LvlFromString(lvl string) (Lvl, error) {
	// Since we also parse python log entries we also have to handle the levels of python.
	switch strings.ToUpper(lvl) {
	case "DEBUG", "DBUG":
		return LvlDebug, nil
	case "INFO":
		return LvlInfo, nil
	case "WARN", "WARNING":
		return LvlWarn, nil
	case "ERROR", "EROR":
		return LvlError, nil
	case "CRIT", "CRITICAL":
		return LvlCrit, nil
	default:
		return LvlDebug, fmt.Errorf("Unknown level: %v", lvl)
	}
}

func (l Lvl) String() string {
	return strings.ToUpper(log15.Lvl(l).String())
}

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
			return common.NewBasicError("Log dir flag not set", nil)
		}
		err = SetupLogFile(name, logDir, logLevel, logSize, logAge, logFlush)
	}
	return err
}

// SetupLogFile initializes a file for logging. The path is logDir/name.log if
// name doesn't already contain the .log extension, or logDir/name otherwise.
// logLevel can be one of debug, info, warn, error, and crit and states the
// minimum level of logging events that get written to the file. logSize is the
// maximum size, in MiB, until the log rotates. logAge is the maximum number of
// days to retain old log files. If logFlush > 0, logging output is buffered,
// and flushed every logFlush seconds.  If logFlush < 0: logging output is
// buffered, but must be manually flushed by calling Flush(). If logFlush = 0
// logging output is unbuffered and Flush() is a no-op.
func SetupLogFile(name string, logDir string, logLevel string, logSize int, logAge int,
	logFlush int) error {

	logLvl, err := log15.LvlFromString(logLevel)
	if err != nil {
		return common.NewBasicError("Unable to parse log.level flag:", err)
	}

	// Strip .log extension s.t. config files can contain the exact filename
	// while not breaking existing behavior for apps that don't contain the
	// extension.
	name = strings.TrimSuffix(name, ".log")
	var fileLogger io.WriteCloser
	fileLogger = &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.log", logDir, name),
		MaxSize:  logSize, // MiB
		MaxAge:   logAge,  // days
	}

	if logFlush != 0 {
		logBuf = newSyncBuf(fileLogger)
		fileLogger = logBuf
	}

	logFileHandler = log15.LvlFilterHandler(logLvl,
		log15.StreamHandler(fileLogger, fmt15.Fmt15Format(nil)))
	setHandlers()

	if logFlush > 0 {
		go func() {
			for range time.Tick(time.Duration(logFlush) * time.Second) {
				Flush()
			}
		}()
	}
	return nil
}

func SetupLogConsole(logConsole string) error {
	logLvl, err := log15.LvlFromString(logConsole)
	if err != nil {
		return common.NewBasicError("Unable to parse log.console flag:", err)
	}
	var cMap map[log15.Lvl]int
	if isatty.IsTerminal(os.Stderr.Fd()) {
		cMap = fmt15.ColorMap
	}
	logConsHandler = log15.LvlFilterHandler(logLvl,
		log15.StreamHandler(os.Stderr, fmt15.Fmt15Format(cMap)))
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

func LogPanicAndExit() {
	if msg := recover(); msg != nil {
		log15.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		Flush()
		os.Exit(255)
	}
}

func Flush() {
	if logBuf != nil {
		logBuf.Flush()
	}
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

func Log(lvl Lvl, msg string, ctx ...interface{}) {
	var logFun func(string, ...interface{})
	switch lvl {
	case LvlDebug:
		logFun = Debug
	case LvlInfo:
		logFun = Info
	case LvlWarn:
		logFun = Warn
	case LvlError:
		logFun = Error
	case LvlCrit:
		logFun = Crit
	}
	logFun(msg, ctx...)
}

func RandId(idlen int) string {
	return logext.RandId(idlen)
}
