// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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
	"strings"

	"github.com/inconshreveable/log15"
)

// Level is the log level.
type Level log15.Lvl

// The different log levels
const (
	LevelCrit  = Level(log15.LvlCrit)
	LevelError = Level(log15.LvlError)
	LevelWarn  = Level(log15.LvlWarn)
	LevelInfo  = Level(log15.LvlInfo)
	LevelDebug = Level(log15.LvlDebug)
)

// LevelFromString parses the log level.
func LevelFromString(lvl string) (Level, error) {
	// Since we also parse python log entries we also have to handle the levels of python.
	switch strings.ToUpper(lvl) {
	case "DEBUG", "DBUG":
		return LevelDebug, nil
	case "INFO":
		return LevelInfo, nil
	case "WARN", "WARNING":
		return LevelWarn, nil
	case "ERROR", "EROR":
		return LevelError, nil
	case "CRIT", "CRITICAL":
		return LevelCrit, nil
	default:
		return LevelDebug, fmt.Errorf("Unknown level: %v", lvl)
	}
}

func (l Level) String() string {
	return strings.ToUpper(log15.Lvl(l).String())
}

const (
	LevelTraceStr = "trace"
	// TraceMsgPrefix is prepended to TRACE level logging messages.
	TraceMsgPrefix = "[TRACE] "
)

// Trace logs at trace level
func Trace(msg string, ctx ...interface{}) {
	Debug(TraceMsgPrefix+msg, ctx...)
}

// Debug logs at debug level.
func Debug(msg string, ctx ...interface{}) {
	log15.Debug(msg, ctx...)
}

// Info logs at info level.
func Info(msg string, ctx ...interface{}) {
	log15.Info(msg, ctx...)
}

// Warn logs at warn level.
func Warn(msg string, ctx ...interface{}) {
	log15.Warn(msg, ctx...)
}

// Error logs at error level.
func Error(msg string, ctx ...interface{}) {
	log15.Error(msg, ctx...)
}

// Crit logs at crit level.
func Crit(msg string, ctx ...interface{}) {
	log15.Crit(msg, ctx...)
}

// Log logs at the given level.
func Log(level Level, msg string, ctx ...interface{}) {
	var logFun func(string, ...interface{})
	switch level {
	case LevelDebug:
		logFun = Debug
	case LevelInfo:
		logFun = Info
	case LevelWarn:
		logFun = Warn
	case LevelError:
		logFun = Error
	case LevelCrit:
		logFun = Crit
	}
	logFun(msg, ctx...)
}

// Logger describes the logger interface.
type Logger interface {
	New(ctx ...interface{}) Logger
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
}

var _ Logger = (*loggerWithTrace)(nil)

type loggerWithTrace struct {
	log15.Logger
}

// New creates a logger with the given context.
func New(ctx ...interface{}) Logger {
	return &loggerWithTrace{Logger: log15.New(ctx...)}
}

// Root returns the root logger. It's a logger without any context.
func Root() Logger {
	return &loggerWithTrace{Logger: log15.Root()}
}

func (logger *loggerWithTrace) Trace(msg string, ctx ...interface{}) {
	logger.Logger.Debug(TraceMsgPrefix+msg, ctx...)
}

func (logger *loggerWithTrace) New(ctx ...interface{}) Logger {
	return &loggerWithTrace{Logger: logger.Logger.New(ctx...)}
}

// Discard sets the logger up to discard all log entries. This is useful for
// testing.
func Discard() {
	Root().(*loggerWithTrace).Logger.SetHandler(log15.DiscardHandler())
}

// Handler wraps log15.Handler, should only be used for testing.
type Handler interface {
	log15.Handler
}

type filterTraceHandler struct {
	log15.Handler
}

func (h *filterTraceHandler) Log(r *log15.Record) error {
	if !strings.HasPrefix(r.Msg, TraceMsgPrefix) {
		return h.Handler.Log(r)
	}
	return nil
}
