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
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

func timeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format(common.TimeFmt))
}

func fmtCaller(caller zapcore.EntryCaller) string {
	p := caller.TrimmedPath()
	if len(p) > 30 {
		p = "..." + p[len(p)-27:]
	}
	return fmt.Sprintf("%30s", p)
}

func fixedCallerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(fmtCaller(caller))
}

// Setup configures the logging library with the given config.
func Setup(cfg Config) error {
	cfg.InitDefaults()
	if err := setupConsole(cfg.Console); err != nil {
		return err
	}
	return nil
}

func convertCfg(cfg ConsoleConfig) (zap.Config, error) {
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		return zap.Config{}, serrors.WrapStr("unable to parse log.console.level", err,
			"level", cfg.Level)
	}
	encoding := "console"
	if cfg.Format == "json" {
		encoding = "json"
	}
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = timeEncoder
	if cfg.Format != "json" {
		encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		encoderConfig.EncodeCaller = fixedCallerEncoder
	}
	return zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableStacktrace: cfg.StacktraceLevel == "none",
		Encoding:          encoding,
		EncoderConfig:     encoderConfig,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}, nil
}

func getStacktraceLvl(cfg ConsoleConfig) (zapcore.LevelEnabler, error) {
	if cfg.StacktraceLevel == "none" {
		return zap.PanicLevel, nil
	}
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(cfg.StacktraceLevel)); err != nil {
		return nil, serrors.WrapStr("unable to parse log.console.stacktrace_level", err,
			"level", cfg.Level)
	}
	return level, nil
}

func setupConsole(cfg ConsoleConfig) error {
	zCfg, err := convertCfg(cfg)
	if err != nil {
		return err
	}
	stacktrace, err := getStacktraceLvl(cfg)
	if err != nil {
		return err
	}
	logger, err := zCfg.Build(zap.AddCallerSkip(1), zap.AddStacktrace(stacktrace))
	if err != nil {
		return serrors.WrapStr("creating logger", err)
	}
	zap.ReplaceGlobals(logger)
	ConsoleLevel = Level{a: zCfg.Level}
	return nil
}

// HandlePanic catches panics and logs them.
func HandlePanic() {
	if msg := recover(); msg != nil {
		// Ugly hack: If this flag is set, we are inside a test.
		// In that case we want to rethrow the exception so that it appears in stdout.
		if flag.Lookup("test.v") != nil {
			panic(msg)
		}
		zap.L().Error("Panic", zap.Any("msg", msg), zap.Stack("stack"))
		zap.L().Error("=====================> Service panicked!")
		Flush()
		os.Exit(255)
	}
}

// Flush writes the logs to the underlying buffer.
func Flush() {
	zap.L().Sync()
}

// ConsoleLevel allows interacting with the logging level at runtime.
// It is initialized with after a successful call to Setup.
var ConsoleLevel Level

// Level allows to interact with the logging level at runtime.
type Level struct {
	a zap.AtomicLevel
}

// ServeHTTP is an endpoint that can report on or change the current logging
// level.
//
// GET requests return a JSON description of the current logging level.
// PUT requests change the logging level and expect a payload like:
//   {"level":"info"}
func (l Level) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.a.ServeHTTP(w, r)
}
