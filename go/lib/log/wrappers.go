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
	LevelError = Level(log15.LvlError)
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
	case "ERROR", "EROR":
		return LevelError, nil
	default:
		return LevelDebug, fmt.Errorf("Unknown level: %v", lvl)
	}
}

func (l Level) String() string {
	return strings.ToUpper(log15.Lvl(l).String())
}

// Debug logs at debug level.
func Debug(msg string, ctx ...interface{}) {
	log15.Debug(msg, ctx...)
}

// Info logs at info level.
func Info(msg string, ctx ...interface{}) {
	log15.Info(msg, ctx...)
}

// Error logs at error level.
func Error(msg string, ctx ...interface{}) {
	log15.Error(msg, ctx...)
}

// Logger describes the logger interface.
type Logger interface {
	New(ctx ...interface{}) Logger
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
}

type logger struct {
	log15.Logger
}

func (l *logger) New(ctx ...interface{}) Logger {
	return &logger{Logger: l.Logger.New(ctx...)}
}

// New creates a logger with the given context.
func New(ctx ...interface{}) Logger {
	return &logger{Logger: log15.New(ctx...)}
}

// Root returns the root logger. It's a logger without any context.
func Root() Logger {
	return &logger{Logger: log15.Root()}
}

// Discard sets the logger up to discard all log entries. This is useful for
// testing.
func Discard() {
	Root().(*logger).Logger.SetHandler(log15.DiscardHandler())
}

// Handler wraps log15.Handler, should only be used for testing.
type Handler interface {
	log15.Handler
}
