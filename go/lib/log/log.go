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
	"os"
	"runtime/debug"
	"strings"

	"github.com/inconshreveable/log15"
	// Allows customization of timestamps and multi-line support
	"github.com/kormat/fmt15"
	"github.com/mattn/go-isatty"

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
	var console log15.Handler
	var err error
	if console, err = setupConsole(cfg.Console); err != nil {
		return err
	}
	setHandlers(console)
	return nil
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

func setHandlers(logConsHandler log15.Handler) {
	var handler log15.Handler
	switch {
	case logConsHandler != nil:
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
