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
	"go.uber.org/zap"
)

// Debug logs at debug level.
func Debug(msg string, ctx ...interface{}) {
	zap.L().Debug(msg, convertCtx(ctx)...)
}

// Info logs at info level.
func Info(msg string, ctx ...interface{}) {
	zap.L().Info(msg, convertCtx(ctx)...)
}

// Error logs at error level.
func Error(msg string, ctx ...interface{}) {
	zap.L().Error(msg, convertCtx(ctx)...)
}

// WithOptions returns the logger with the options applied.
func WithOptions(opts ...Option) Logger {
	co := applyOptions(opts)
	return &logger{logger: zap.L().WithOptions(co.zapOptions()...)}
}

// Logger describes the logger interface.
type Logger interface {
	New(ctx ...interface{}) Logger
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
}

type logger struct {
	logger *zap.Logger
}

// New creates a logger with the given context.
func New(ctx ...interface{}) Logger {
	return &logger{logger: zap.L().With(convertCtx(ctx)...)}
}

func (l *logger) New(ctx ...interface{}) Logger {
	return &logger{logger: l.logger.With(convertCtx(ctx)...)}
}

func (l *logger) Debug(msg string, ctx ...interface{}) {
	l.logger.Debug(msg, convertCtx(ctx)...)
}

func (l *logger) Info(msg string, ctx ...interface{}) {
	l.logger.Info(msg, convertCtx(ctx)...)
}

func (l *logger) Error(msg string, ctx ...interface{}) {
	l.logger.Error(msg, convertCtx(ctx)...)
}

// Root returns the root logger. It's a logger without any context.
func Root() Logger {
	return &logger{logger: zap.L()}
}

// Discard sets the logger up to discard all log entries. This is useful for
// testing.
func Discard() {
	Root().(*logger).logger = zap.NewNop()
}

// DiscardLogger implements the Logger interface and discards all messages.
// Subloggers created from this logger will also discard all messages and
// ignore the additional context.
//
// To see how to use this, see the example.
type DiscardLogger struct{}

func (d DiscardLogger) New(ctx ...interface{}) Logger      { return d }
func (DiscardLogger) Debug(msg string, ctx ...interface{}) {}
func (DiscardLogger) Info(msg string, ctx ...interface{})  {}
func (DiscardLogger) Error(msg string, ctx ...interface{}) {}

func convertCtx(ctx []interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(ctx)/2)
	for i := 0; i+1 < len(ctx); i += 2 {
		fields = append(fields, zap.Any(ctx[i].(string), ctx[i+1]))
	}
	return fields
}
