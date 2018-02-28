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
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/kormat/fmt15" // Allows customization of timestamps and multi-line support
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/scionproto/scion/go/lib/common"
)

var (
	logDir     string
	logLevel   string
	logConsole string
	logSize    int
	logAge     int
	logFlush   int
	logBuf     *syncBuf
)

func init() {
	os.Setenv("TZ", "UTC")
	fmt15.TimeFmt = common.TimeFmt
}

func Setup(name string) {
	logLvl, consLvl := parseLvls()
	logBuf = newSyncBuf(mkLogfile(name))
	handler := log.MultiHandler(
		log.LvlFilterHandler(logLvl, log.StreamHandler(logBuf, fmt15.Fmt15Format(nil))),
		log.LvlFilterHandler(consLvl, log.StreamHandler(os.Stdout,
			fmt15.Fmt15Format(fmt15.ColorMap))),
	)
	log.Root().SetHandler(handler)
	go func() {
		for range time.Tick(time.Duration(logFlush) * time.Second) {
			Flush()
		}
	}()
}

func AddDefaultLogFlags() {
	flag.StringVar(&logDir, "log.dir", "logs", "Log directory")
	flag.StringVar(&logLevel, "log.level", "debug", "Logging level")
	flag.StringVar(&logConsole, "log.console", "crit", "Console logging level")
	flag.IntVar(&logSize, "log.size", 50, "Max size of log file in MiB")
	flag.IntVar(&logAge, "log.age", 7, "Max age of log file in days")
	flag.IntVar(&logFlush, "log.flush", 5, "How frequently to flush to the log file, in seconds")
}

func parseLvls() (log.Lvl, log.Lvl) {
	logLvl, err := log.LvlFromString(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Level flag: %v", err)
		os.Exit(1)
	}
	consLvl, err := log.LvlFromString(logConsole)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse log.Console flag: %v", err)
		os.Exit(1)
	}
	return logLvl, consLvl
}

func mkLogfile(name string) io.WriteCloser {
	return &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.log", logDir, name),
		MaxSize:  logSize, // MiB
		MaxAge:   logAge,  // days
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
