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
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/inconshreveable/log15"
	// Allows customization of timestamps and multi-line support
	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

func init() {
	fmt15.TimeFmt = common.TimeFmt
}

var logBuf *syncBuf

// Setup configures the logging library with the given config.
func Setup(cfg Config) error {
	cfg.InitDefaults()
	var file, console log15.Handler
	var err error
	if file, err = setupFile(cfg.File); err != nil {
		return err
	}
	if console, err = setupConsole(cfg.Console); err != nil {
		return err
	}
	setHandlers(file, console)
	return nil
}

func setupFile(cfg FileConfig) (log15.Handler, error) {
	if cfg.Path == "" {
		return nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Path), os.ModePerm); err != nil {
		return nil, serrors.WrapStr("unable create log directory", err,
			"dir", filepath.Dir(cfg.Path))
	}

	logLvl, err := log15.LvlFromString(cfg.Level)
	if err != nil {
		return nil, serrors.WrapStr("unable to parse log.file.level", err, "level", cfg.Level)
	}

	var logger io.WriteCloser
	logger = &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    int(cfg.Size),   // MiB
		MaxAge:     int(cfg.MaxAge), // days
		MaxBackups: int(cfg.MaxBackups),
		Compress:   cfg.Compress,
	}

	if cfg.FlushInterval != nil {
		logBuf = newSyncBuf(logger)
		logger = logBuf
	}
	format := fmt15.Fmt15Format(nil)
	if strings.EqualFold(cfg.Format, "json") {
		format = log15.JsonFormat()
	}
	handler := log15.LvlFilterHandler(logLvl, log15.StreamHandler(logger, format))

	if cfg.FlushInterval != nil && *cfg.FlushInterval > 0 {
		go func() {
			defer HandlePanic()
			for range time.Tick(time.Duration(*cfg.FlushInterval) * time.Second) {
				Flush()
			}
		}()
	}
	return handler, nil
}

func setupConsole(cfg ConsoleConfig) (log15.Handler, error) {
	lvl, err := log15.LvlFromString(cfg.Level)
	if err != nil {
		return nil, serrors.WrapStr("unable to parse log.console.level", err, "level", cfg.Level)
	}
	var cMap map[log15.Lvl]int
	if isatty.IsTerminal(os.Stderr.Fd()) {
		cMap = fmt15.ColorMap
	}
	format := fmt15.Fmt15Format(cMap)
	if strings.EqualFold(cfg.Format, "json") {
		format = log15.JsonFormat()
	}
	handler := log15.LvlFilterHandler(lvl, log15.StreamHandler(os.Stderr, format))
	return handler, nil
}

func setHandlers(logFileHandler, logConsHandler log15.Handler) {
	var handler log15.Handler
	switch {
	case logFileHandler != nil && logConsHandler != nil:
		handler = log15.MultiHandler(logFileHandler, logConsHandler)
	case logFileHandler != nil: // logConsHandler == nil
		handler = logFileHandler
	case logConsHandler != nil: // logFileHandler == nil
		handler = logConsHandler
	}
	log15.Root().SetHandler(handler)
}

// HandlePanic catches panics and logs them.
func HandlePanic() {
	if msg := recover(); msg != nil {
		log15.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		log15.Crit("=====================> Service panicked!")
		Flush()
		os.Exit(255)
	}
}

// Flush writes the logs to the underlying buffer.
func Flush() {
	if logBuf != nil {
		logBuf.Flush()
	}
}
