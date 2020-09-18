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
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync/atomic"

	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/lib/common"
	libconfig "github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/sigdisp"
	"github.com/scionproto/scion/go/lib/sigjson"
	"github.com/scionproto/scion/go/pkg/service"
	sigconfig "github.com/scionproto/scion/go/pkg/sig/config"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/internal/base"
	"github.com/scionproto/scion/go/sig/internal/ingress"
	"github.com/scionproto/scion/go/sig/internal/metrics"
	"github.com/scionproto/scion/go/sig/internal/sigcmn"
	"github.com/scionproto/scion/go/sig/internal/xnet"
)

var (
	cfg sigconfig.Config
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
	if err := setupBasic(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer log.Flush()
	defer env.LogAppStopped("SIG", cfg.Sig.ID)
	defer log.HandlePanic()
	if err := cfg.Validate(); err != nil {
		log.Error("Configuration validation failed", "err", err)
		return 1
	}
	// Setup tun early so that we can drop capabilities before interacting with network etc.
	tunIO, err := setupTun()
	if err != nil {
		log.Error("TUN device initialization failed", "err", err)
		return 1
	}
	if err := sigcmn.Init(cfg.Sig, cfg.Sciond, cfg.Features); err != nil {
		log.Error("SIG common initialization failed", "err", err)
		return 1
	}
	env.SetupEnv(
		func() {
			success := loadConfig(cfg.Sig.SIGConfig)
			// Errors already logged in loadConfig
			log.Info("reloadOnSIGHUP: reload done", "success", success)
		},
	)
	sigdisp.Init(sigcmn.CtrlConn, false)
	// Parse sig config
	if loadConfig(cfg.Sig.SIGConfig) != true {
		log.Error("SIG configuration loading failed")
		return 1
	}
	// Reply to probes from other SIGs.
	go func() {
		defer log.HandlePanic()
		base.PollReqHdlr()
	}()
	egress.Init(tunIO)
	ingress.Init(tunIO)

	// Start HTTP endpoints.
	statusPages := service.StatusPages{
		"info":      service.NewInfoHandler(),
		"config":    service.NewConfigHandler(cfg),
		"log/level": log.ConsoleLevel.ServeHTTP,
	}
	if err := statusPages.Register(http.DefaultServeMux, cfg.Sig.ID); err != nil {
		log.Error("registering status pages", "err", err)
		return 1
	}
	cfg.Metrics.StartPrometheus()

	select {
	case <-fatal.ShutdownChan():
		return 0
	case <-fatal.FatalChan():
		return 1
	}
}

// setupBasic loads the config from file and initializes logging.
func setupBasic() error {
	// Load and initialize config.
	if err := libconfig.LoadFile(env.ConfigFile(), &cfg); err != nil {
		return serrors.WrapStr("Failed to load config", err, "file", env.ConfigFile())
	}
	cfg.InitDefaults()
	if err := log.Setup(cfg.Logging); err != nil {
		return serrors.WrapStr("Failed to initialize logging", err)
	}
	prom.ExportElementID(cfg.Sig.ID)
	return env.LogAppStarted("SIG", cfg.Sig.ID)
}

func setupTun() (io.ReadWriteCloser, error) {
	if err := checkPerms(); err != nil {
		return nil, serrors.WrapStr("Permissions checks failed", err)
	}
	tunLink, tunIO, err := xnet.ConnectTun(cfg.Sig.Tun)
	if err != nil {
		return nil, err
	}
	src := cfg.Sig.SrcIP4
	if len(src) == 0 && sigcmn.CtrlAddr.To4() != nil {
		src = sigcmn.CtrlAddr
	}
	if err = xnet.AddRoute(cfg.Sig.TunRTableId, tunLink, sigcmn.DefV4Net, src); err != nil {
		return nil,
			common.NewBasicError("Unable to add default IPv4 route to SIG routing table", err)
	}
	src = cfg.Sig.SrcIP6
	if len(src) == 0 && sigcmn.CtrlAddr.To16() != nil && sigcmn.CtrlAddr.To4() == nil {
		src = sigcmn.CtrlAddr
	}
	if len(src) != 0 {
		if err = xnet.AddRoute(cfg.Sig.TunRTableId, tunLink, sigcmn.DefV6Net, src); err != nil {
			return nil,
				common.NewBasicError("Unable to add default IPv6 route to SIG routing table", err)
		}
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
	caps, err := capability.NewPid(0)
	if err != nil {
		return common.NewBasicError("Error retrieving capabilities", err)
	}
	log.Info("Startup capabilities", "caps", caps)
	if !caps.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {
		return common.NewBasicError("CAP_NET_ADMIN is required", nil, "caps", caps)
	}
	return nil
}

func loadConfig(path string) bool {
	cfg, err := sigjson.LoadFromFile(path)
	if err != nil {
		log.Error("loadConfig: Failed", "err", err)
		return false
	}
	ok := egress.ReloadConfig(cfg)
	if !ok {
		return false
	}
	atomic.StoreUint64(&metrics.ConfigVersion, cfg.ConfigVersion)
	return true
}
