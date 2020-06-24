// Copyright 2020 Anapaya Systems
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
	"os"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/cs"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	defer log.Flush()
	fatal.Init()

	env.AddFlags()
	flag.BoolVar(&cs.HelpPolicy, "help-policy", false, "Output sample policy file.")
	flag.Parse()
	if code, ok := cs.CheckFlags(&cs.Cfg); !ok {
		return code
	}

	if err := InitConfiguration(); err != nil {
		log.Error("Configuration initialization failed", "err", err)
		return 1
	}

	app := &cs.App{}
	return app.Run()
}

// InitConfiguration sets up the application's configuration based
// on environment variables, command line arguments and the configuration
// files.
func InitConfiguration() error {
	if err := config.LoadFile(env.ConfigFile(), &cs.Cfg); err != nil {
		return serrors.WrapStr("failed to load config", err, "file", env.ConfigFile())
	}
	cs.Cfg.InitDefaults()

	if err := cs.InitLogging(); err != nil {
		return serrors.WrapStr("unable to initialize logging", err)
	}

	return nil
}
