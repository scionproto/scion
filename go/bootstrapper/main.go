package main

import (
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
)

import (
	"github.com/BurntSushi/toml"
	"github.com/scionproto/scion/go/bootstrapper/config"
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
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		fmt.Fprintln(os.Stderr, err)
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
	err := tryBootstrapping()
	if err != nil {
		log.Error("Bootstrapping failed", "err", err)
		return 1
	}

	return 0
}
