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
	"fmt"
	"os"

	"github.com/scionproto/scion/go/bootstrapper/config"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/proto"
)

var (
	cfg config.Config
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	fatal.Init()
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(&cfg); !ok {
		return v
	}
	if err := libconfig.LoadFile(env.ConfigFile(), &cfg); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("bootstrapper", "")
	defer log.HandlePanic()

	if err := cfg.Validate(); err != nil {
		log.Error("Unable to validate config", "err", err)
		return 1
	}
	itopo.Init(&itopo.Config{ID: "", Svc: proto.ServiceType_unset, Callbacks: itopo.Callbacks{}})
	b, err := NewBootstrapper(&cfg)
	if err != nil {
		log.Error("Error creating bootstrapper", "err", err)
		return 1
	}
	if err := b.tryBootstrapping(); err != nil {
		log.Error("Bootstrapping failed", "err", err)
		return 1
	}
	return 0
}
