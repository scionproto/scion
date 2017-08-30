// Copyright 2016 ETH Zurich
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

package liblog

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/kormat/fmt15" // Allows customization of timestamps and multi-line support
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/netsec-ethz/scion/go/lib/common"
)

var logDir = flag.String("log.dir", "logs", "Log directory")
var logLevel = flag.String("log.level", "debug", "Logging level")
var logConsole = flag.String("log.console", "crit", "Console logging level")
var logSize = flag.Int("log.size", 50, "Max size of log file in MiB")
var logAge = flag.Int("log.age", 7, "Max age of log file in days")

var logBuf *bufio.Writer

func init() {
	os.Setenv("TZ", "UTC")
	fmt15.TimeFmt = common.TimeFmt
}

func Setup(name string) {
	logLvl, consLvl := parseLvls()
	logBuf = bufio.NewWriter(mkLogfile(name))
	handler := log.MultiHandler(
		log.LvlFilterHandler(logLvl, log.StreamHandler(logBuf, fmt15.Fmt15Format(nil))),
		log.LvlFilterHandler(consLvl, log.StreamHandler(os.Stdout,
			fmt15.Fmt15Format(fmt15.ColorMap))),
	)
	log.Root().SetHandler(handler)
	go func() {
		for range time.Tick(5 * time.Second) {
			Flush()
		}
	}()
}

func parseLvls() (log.Lvl, log.Lvl) {
	logLvl, err := log.LvlFromString(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Level flag: %v", err)
		os.Exit(1)
	}
	consLvl, err := log.LvlFromString(*logConsole)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Console flag: %v", err)
		os.Exit(1)
	}
	return logLvl, consLvl
}

func mkLogfile(name string) io.Writer {
	return &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.log", *logDir, name),
		MaxSize:  50, // MiB
		MaxAge:   7,  // days
	}
}

func LogPanicAndExit() {
	if msg := recover(); msg != nil {
		log.Crit("Panic", "msg", msg, "stack", string(debug.Stack()))
		Flush()
		os.Exit(255)
	}
}

func Flush() {
	logBuf.Flush()
}
