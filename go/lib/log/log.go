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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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
func Setup(cfg Config, opts ...Option) error {
	cfg.InitDefaults()
	if err := setupConsole(cfg.Console, applyOptions(opts)); err != nil {
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
		DisableCaller:     cfg.DisableCaller,
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

func setupConsole(cfg ConsoleConfig, opts options) error {
	zCfg, err := convertCfg(cfg)
	if err != nil {
		return err
	}
	stacktrace, err := getStacktraceLvl(cfg)
	if err != nil {
		return err
	}

	zapOpts := []zap.Option{
		zap.AddCallerSkip(1),
		zap.AddStacktrace(stacktrace),
	}
	zapOpts = append(zapOpts, opts.zapOptions()...)

	logger, err := zCfg.Build(zapOpts...)
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
	type errorResponse struct {
		Error string `json:"error"`
	}
	type payload struct {
		Level *zapcore.Level `json:"level"`
	}
	enc := json.NewEncoder(w)
	switch r.Method {
	case http.MethodGet:
		lvl := l.a.Level()
		enc.Encode(payload{Level: &lvl})
	case http.MethodPut:
		lvl, err := func() (*zapcore.Level, error) {
			switch r.Header.Get("Content-Type") {
			case "application/x-www-form-urlencoded":
				body, err := ioutil.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				values, err := url.ParseQuery(string(body))
				if err != nil {
					return nil, err
				}
				lvl := values.Get("level")
				if lvl == "" {
					return nil, serrors.New("must specify logging level")
				}
				var l zapcore.Level
				if err := l.UnmarshalText([]byte(lvl)); err != nil {
					return nil, err
				}
				return &l, nil
			default:
				var pld payload
				if err := json.NewDecoder(r.Body).Decode(&pld); err != nil {
					return nil, fmt.Errorf("malformed request body: %v", err)
				}
				if pld.Level == nil {
					return nil, serrors.New("must specify logging level")
				}
				return pld.Level, nil
			}
		}()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			enc.Encode(errorResponse{Error: err.Error()})
			return
		}
		l.a.SetLevel(*lvl)
		enc.Encode(payload{Level: lvl})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		enc.Encode(errorResponse{
			Error: fmt.Sprintf("HTTP method not supported: %v", r.Method),
		})
	}
}

// SafeNewLogger creates a new logger as a child of l only if l is not nil. If l is nil, then
// nil is returned.
func SafeNewLogger(l Logger, fields ...interface{}) Logger {
	if l != nil {
		return l.New(fields...)
	}
	return nil
}

// SafeDebug logs to l only if l is not nil.
func SafeDebug(l Logger, msg string, fields ...interface{}) {
	if l != nil {
		if ll, ok := l.(*logger); ok {
			ll.logger.Debug(msg, convertCtx(fields)...)
			return
		}
		l.Debug(msg, fields...)
	}
}

// SafeInfo logs to l only if l is not nil.
func SafeInfo(l Logger, msg string, fields ...interface{}) {
	if l != nil {
		if ll, ok := l.(*logger); ok {
			ll.logger.Info(msg, convertCtx(fields)...)
			return
		}
		l.Info(msg, fields...)
	}
}

// SafeError logs to l only if l is not nil.
func SafeError(l Logger, msg string, fields ...interface{}) {
	if l != nil {
		if ll, ok := l.(*logger); ok {
			ll.logger.Error(msg, convertCtx(fields)...)
			return
		}
		l.Error(msg, fields...)
	}
}
