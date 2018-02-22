// Copyright 2018 ETH Zurich
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
package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	log "github.com/inconshreveable/log15"
	"github.com/kormat/fmt15" // Allows customization of timestamps and multi-line support
)

func customFormat(buf *bytes.Buffer, r *log.Record, color int) {
	lvlStr := fmt15.ColorStr(strings.ToUpper(r.Lvl.String()), color)
	if r.Lvl == log.LvlInfo {
		fmt.Fprintf(buf, "%v", r.Msg)
	} else {
		fmt.Fprintf(buf, "[%v] %v", lvlStr, r.Msg)
	}

	for i := 0; i < len(r.Ctx); i += 2 {
		k, ok := r.Ctx[i].(string)
		v := fmt15.FmtValue(r.Ctx[i+1])
		if !ok {
			k, v = fmt15.ErrorKey, fmt.Sprintf("\"Key(%T) is not a string: %v\"", r.Ctx[i], r.Ctx[i])
		}
		fmt.Fprintf(buf, " %v=%v", fmt15.ColorStr(k, color), v)
	}
}

func logFormat() log.Format {
	return log.FormatFunc(func(r *log.Record) []byte {
		color := fmt15.ColorMap[r.Lvl]
		buf := &bytes.Buffer{}
		customFormat(buf, r, color)
		raw := buf.Bytes()
		if raw[len(raw)-1] != '\n' {
			// Add a trailing newline, if the output doesn't already have one.
			raw = append(raw, '\n')
		}
		return raw
	})
}

func logSetup() {
	logLvl, err := log.LvlFromString(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse logLevel flag: %v", err)
		os.Exit(1)
	}
	handler := log.LvlFilterHandler(logLvl, log.StreamHandler(os.Stdout, logFormat()))
	log.Root().SetHandler(handler)
}

func logFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func logPanicAndExit() {
	if msg := recover(); msg != nil {
		log.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		os.Exit(255)
	}
}
