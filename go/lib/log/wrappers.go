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
	"fmt"
	"strings"

	"github.com/inconshreveable/log15"
	logext "github.com/inconshreveable/log15/ext"
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

const (
	LvlTraceStr = "trace"
	// TraceMsgPrefix is prepended to TRACE level logging messages.
	TraceMsgPrefix = "[TRACE] "
)

func Trace(msg string, ctx ...interface{}) {
	Debug(TraceMsgPrefix+msg, ctx...)
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

type Logger interface {
	New(ctx ...interface{}) Logger
	GetHandler() Handler
	SetHandler(h Handler)
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

func New(ctx ...interface{}) Logger {
	return &loggerWithTrace{Logger: log15.New(ctx...)}
}

func Root() Logger {
	return &loggerWithTrace{Logger: log15.Root()}
}

func (logger *loggerWithTrace) Trace(msg string, ctx ...interface{}) {
	logger.Logger.Debug(TraceMsgPrefix+msg, ctx...)
}

func (logger *loggerWithTrace) New(ctx ...interface{}) Logger {
	return &loggerWithTrace{Logger: logger.Logger.New(ctx...)}
}

func (logger *loggerWithTrace) SetHandler(h Handler) {
	logger.Logger.SetHandler(h)
}

func (logger *loggerWithTrace) GetHandler() Handler {
	return logger.Logger.GetHandler()
}

type Handler interface {
	log15.Handler
}

func DiscardHandler() Handler {
	return log15.DiscardHandler()
}

var _ Handler = (*filterTraceHandler)(nil)

type filterTraceHandler struct {
	log15.Handler
}

func FilterTraceHandler(handler log15.Handler) log15.Handler {
	return &filterTraceHandler{Handler: handler}
}

func (h *filterTraceHandler) Log(r *log15.Record) error {
	if !strings.HasPrefix(r.Msg, TraceMsgPrefix) {
		return h.Handler.Log(r)
	}
	return nil
}

func RandId(idlen int) string {
	return logext.RandId(idlen)
}
