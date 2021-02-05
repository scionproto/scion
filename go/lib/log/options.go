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

func (opts *options) zapOptions() []zap.Option {
	if opts.entriesCounter == nil {
		return nil
	}
	return []zap.Option{zap.Hooks(opts.entriesCounter.hook)}
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
