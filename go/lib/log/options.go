// Copyright 2021 Anapaya Systems
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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/scionproto/scion/go/lib/metrics"
)

type options struct {
	entriesCounter *EntriesCounter
	callerSkip     int
}

func applyOptions(opts []Option) options {
	o := options{}
	for _, option := range opts {
		option(&o)
	}
	return o
}

// Option is a function that sets an option.
type Option func(o *options)

// WithEntriesCounter configures a metric counters that are incremented with
// every emitted log entry.
func WithEntriesCounter(m EntriesCounter) Option {
	return func(o *options) {
		o.entriesCounter = &m
	}
}

// AddCallerSkip increases the number of callers skipped by caller annotation.
// When building wrappers around the Logger, supplying this Option prevents the
// Logger from always reporting the wrapper code as the caller.
func AddCallerSkip(skip int) Option {
	return func(o *options) {
		o.callerSkip = skip
	}
}

func (opts *options) zapOptions() []zap.Option {
	var zapOpts []zap.Option
	if opts.entriesCounter != nil {
		zapOpts = append(zapOpts, zap.Hooks(opts.entriesCounter.hook))
	}
	if opts.callerSkip != 0 {
		zapOpts = append(zapOpts, zap.AddCallerSkip(opts.callerSkip))
	}
	return zapOpts
}

// EntriesCounter defines the metrics that are incremented when emitting a log
// entry.
type EntriesCounter struct {
	Debug metrics.Counter
	Info  metrics.Counter
	Error metrics.Counter
}

func (m *EntriesCounter) hook(e zapcore.Entry) error {
	switch e.Level {
	case zapcore.ErrorLevel:
		metrics.CounterInc(m.Error)
	case zapcore.InfoLevel:
		metrics.CounterInc(m.Info)
	case zapcore.DebugLevel:
		metrics.CounterInc(m.Debug)
	}
	return nil
}
