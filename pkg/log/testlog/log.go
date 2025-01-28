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

package testlog

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"

	"github.com/scionproto/scion/pkg/log"
)

// NewLogger builds a new Logger that logs all messages to the given testing.TB.
func NewLogger(t testing.TB, opts ...zaptest.LoggerOption) log.Logger {
	return &logger{
		logger: zaptest.NewLogger(t, opts...),
	}
}

type logger struct {
	logger *zap.Logger
}

// New creates a logger with the given context.
func New(ctx ...any) log.Logger {
	return &logger{logger: zap.L().With(convertCtx(ctx)...)}
}

func (l *logger) New(ctx ...any) log.Logger {
	return &logger{logger: l.logger.With(convertCtx(ctx)...)}
}

func (l *logger) Debug(msg string, ctx ...any) {
	l.logger.Debug(msg, convertCtx(ctx)...)
}

func (l *logger) Info(msg string, ctx ...any) {
	l.logger.Info(msg, convertCtx(ctx)...)
}

func (l *logger) Error(msg string, ctx ...any) {
	l.logger.Error(msg, convertCtx(ctx)...)
}

func (l *logger) Enabled(lvl log.Level) bool {
	return l.logger.Core().Enabled(zapcore.Level(lvl))
}

func convertCtx(ctx []any) []zap.Field {
	fields := make([]zap.Field, 0, len(ctx)/2)
	for i := 0; i+1 < len(ctx); i += 2 {
		fields = append(fields, zap.Any(ctx[i].(string), ctx[i+1]))
	}
	return fields
}
