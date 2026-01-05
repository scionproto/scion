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
	Logger Logger
	Span   opentracing.Span
}

// Debug logs to the logger and span.
func (s Span) Debug(msg string, ctx ...any) {
	s.Logger.Debug(msg, ctx...)
	s.spanLog("debug", msg, ctx...)
}

// Info logs to the logger and span.
func (s Span) Info(msg string, ctx ...any) {
	s.Logger.Info(msg, ctx...)
	s.spanLog("info", msg, ctx...)
}

// Error logs to the logger and span.
func (s Span) Error(msg string, ctx ...any) {
	s.Logger.Error(msg, ctx...)
	s.spanLog("error", msg, ctx...)
}

func (s Span) Enabled(lvl Level) bool {
	return s.Logger.Enabled(lvl)
}

// New creates a new logger with the context attached.
func (s Span) New(ctx ...any) Logger {
	return Span{
		Logger: s.Logger.New(ctx...),
		Span:   s.Span,
	}
}

func (s Span) spanLog(lvl, msg string, ctx ...any) {
	if s.Span == nil {
		return
	}
	s.Span.LogKV(append([]any{"level", lvl, "event", msg}, ctx...)...)
}
