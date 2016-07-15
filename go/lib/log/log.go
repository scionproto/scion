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
	"runtime/debug"

	log "github.com/Sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logDir = flag.String("log.dir", "logs", "Log directory")

func Setup(name string) {
	log.SetFormatter(&UTCFormatter{})
	lj := &lumberjack.Logger{
		Filename: fmt.Sprintf("%s/%s.log", *logDir, name),
		MaxSize:  50, // MiB
		MaxAge:   7,  // days
	}
	log.SetOutput(lj)
}

func PanicLog() {
	if err := recover(); err != nil {
		log.Fatalf("Panic: %s\n%s", err, debug.Stack())
	}
}
