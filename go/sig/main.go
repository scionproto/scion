// Copyright 2017 ETH Zurich
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

package main

import (
	"flag"
	"fmt"
	"io"
	_ "net/http/pprof"
	"os"
	"os/user"
	"sync/atomic"

	"github.com/BurntSushi/toml"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/sig/base"
	"github.com/scionproto/scion/go/sig/base/core"
	"github.com/scionproto/scion/go/sig/config"
	"github.com/scionproto/scion/go/sig/disp"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/egress/reader"
	"github.com/scionproto/scion/go/sig/ingress"
	"github.com/scionproto/scion/go/sig/internal/sigconfig"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/xnet"
)

type Config struct {
	Logging env.Logging
	Metrics env.Metrics
	Sciond  env.SciondClient `toml:"sd_client"`
	Sig     sigconfig.Conf
}

var (
	cfg Config
)

func init() {
	flag.Usage = env.Usage
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	env.AddFlags()
	flag.Parse()
	if v, ok := env.CheckFlags(sigconfig.Sample); !ok {
		return v
	}
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer env.CleanupLog()
	defer env.LogSvcStopped("SIG", cfg.Sig.ID)
	if err := validateConfig(); err != nil {
		log.Crit("Validation of config failed", "err", err)
		return 1
	}
	// Setup tun early so that we can drop capabilities before interacting with network etc.
	tunIO, err := setupTun()
	if err != nil {
		log.Crit("Unable to create & configure TUN device", "err", err)
		return 1
	}
	if err := setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		return 1
	}
	go func() {
		defer log.LogPanicAndExit()
		base.PollReqHdlr()
	}()
	environment := env.SetupEnv(
		func() {
			success := loadConfig(cfg.Sig.SIGConfig)
			// Errors already logged in loadConfig
			log.Info("reloadOnSIGHUP: reload done", "success", success)
		},
	)
	// Spawn egress reader
	go func() {
		defer log.LogPanicAndExit()
		reader.NewReader(tunIO).Run()
	}()
	spawnIngressDispatcher(tunIO)
	cfg.Metrics.StartPrometheus(fatal.Chan())
	select {
	case <-environment.AppShutdownSignal:
		return 0
	case err := <-fatal.Chan():
		// Prometheus or the ingress dispatcher encountered a fatal error, thus we exit.
		log.Crit("Fatal error during execution", "err", err)
		return 1
	}
}

// setupBasic loads the config from file and initializes logging.
func setupBasic() error {
	// Load and initialize config.
	if _, err := toml.DecodeFile(env.ConfigFile(), &cfg); err != nil {
		return err
	}
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}
	return env.LogSvcStarted("SIG", cfg.Sig.ID)
}

func validateConfig() error {
	if err := cfg.Sig.Validate(); err != nil {
		return err
	}
	env.InitSciondClient(&cfg.Sciond)
	cfg.Sig.InitDefaults()
	if cfg.Metrics.Prometheus == "" {
		cfg.Metrics.Prometheus = "127.0.0.1:1281"
	}
	return nil
}

func setupTun() (io.ReadWriteCloser, error) {
	if err := checkPerms(); err != nil {
		return nil, common.NewBasicError("Permissions checks failed", nil)
	}
	tunLink, tunIO, err := xnet.ConnectTun(cfg.Sig.Tun)
	if err != nil {
		return nil, err
	}
	src := cfg.Sig.SrcIP4
	if len(src) == 0 && cfg.Sig.IP.To4() != nil {
		src = cfg.Sig.IP
	}
	if err = xnet.AddRoute(cfg.Sig.TunRTableId, tunLink, sigcmn.DefV4Net, src); err != nil {
		return nil,
			common.NewBasicError("Unable to add default IPv4 route to SIG routing table", err)
	}
	src = cfg.Sig.SrcIP6
	if len(src) == 0 && cfg.Sig.IP.To16() != nil && cfg.Sig.IP.To4() == nil {
		src = cfg.Sig.IP
	}
	if err = xnet.AddRoute(cfg.Sig.TunRTableId, tunLink, sigcmn.DefV6Net, src); err != nil {
		return nil,
			common.NewBasicError("Unable to add default IPv6 route to SIG routing table", err)
	}
	// Now that everything is set up, drop CAP_NET_ADMIN
	caps, err := capability.NewPid(0)
	if err != nil {
		return nil, common.NewBasicError("Error retrieving capabilities", err)
	}
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)
	return tunIO, nil
}

func checkPerms() error {
	user, err := user.Current()
	if err != nil {
		return common.NewBasicError("Error retrieving user", err)
	}
	if user.Uid == "0" {
		return common.NewBasicError("Running as root is not allowed for security reasons", nil)
	}
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewBasicError("Error retrieving capabilities", err)
	}
	log.Debug("Startup capabilities", "caps", caps)
	if !caps.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {
		return common.NewBasicError("CAP_NET_ADMIN is required", nil, "caps", caps)
	}
	return nil
}

func setup() error {
	// Export prometheus metrics.
	metrics.Init(cfg.Sig.ID)
	if err := sigcmn.Init(cfg.Sig, cfg.Sciond); err != nil {
		return common.NewBasicError("Error during initialization", err)
	}
	egress.Init()
	disp.Init(sigcmn.CtrlConn)
	// Parse sig config
	if loadConfig(cfg.Sig.SIGConfig) != true {
		return common.NewBasicError("Unable to load sig config on startup", nil)
	}
	return nil
}

func loadConfig(path string) bool {
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		log.Error("loadConfig: Failed", "err", err)
		return false
	}
	ok := core.Map.ReloadConfig(cfg)
	if !ok {
		return false
	}
	atomic.StoreUint64(&metrics.ConfigVersion, cfg.ConfigVersion)
	return true
}

func spawnIngressDispatcher(tunIO io.ReadWriteCloser) {
	d := ingress.NewDispatcher(tunIO)
	go func() {
		if err := d.Run(); err != nil {
			log.Crit("Ingress dispatcher error", "err", err)
			fatal.Fatal(err)
		}
	}()
}
