// Copyright 2019 Anapaya Systems
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
	"github.com/opentracing/opentracing-go"
)

// Span is a logger that attaches all logs to the span.
type Span struct {
	Logger
	Span opentracing.Span
}

// Trace logs to the logger and span.
func (s Span) Trace(msg string, ctx ...interface{}) {
	s.Logger.Debug(TraceMsgPrefix+msg, ctx...)
	s.spanLog("trace", msg, ctx...)
}

// Debug logs to the logger and span.
func (s Span) Debug(msg string, ctx ...interface{}) {
	s.Logger.Debug(msg, ctx...)
	s.spanLog("debug", msg, ctx...)
}

// Info logs to the logger and span.
func (s Span) Info(msg string, ctx ...interface{}) {
	s.Logger.Info(msg, ctx...)
	s.spanLog("info", msg, ctx...)
}

// Warn logs to the logger and span.
func (s Span) Warn(msg string, ctx ...interface{}) {
	s.Logger.Warn(msg, ctx...)
	s.spanLog("warn", msg, ctx...)
}

// Error logs to the logger and span.
func (s Span) Error(msg string, ctx ...interface{}) {
	s.Logger.Error(msg, ctx...)
	s.spanLog("error", msg, ctx...)
}

// Crit logs to the logger and span.
func (s Span) Crit(msg string, ctx ...interface{}) {
	s.Logger.Crit(msg, ctx...)
	s.spanLog("crit", msg, ctx...)
}

func (s Span) spanLog(lvl, msg string, ctx ...interface{}) {
	if s.Span == nil {
		return
	}
	s.Span.LogKV(append([]interface{}{"level", lvl, "event", msg}, ctx...)...)
}
