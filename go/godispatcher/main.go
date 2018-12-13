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
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/godispatcher/internal/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
)

type Config struct {
	Logging    env.Logging
	Metrics    env.Metrics
	Dispatcher config.Config
}

var (
	cfg Config
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if returnCode, ok := env.CheckFlags(config.Sample); !ok {
		return returnCode
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("Dispatcher", cfg.Dispatcher.ID)
	defer log.LogPanicAndExit()

	cfg.Metrics.StartPrometheus()
	<-fatal.Chan()
	return 1
}

func setupBasic() error {
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	env.LogAppStarted("Dispatcher", cfg.Dispatcher.ID)
	return nil
}
