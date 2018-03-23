// Copyright 2017 ETH Zurich
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
	"io"
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"os/user"
	"sync/atomic"
	"syscall"

	log "github.com/inconshreveable/log15"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/sig/base"
	"github.com/scionproto/scion/go/sig/config"
	"github.com/scionproto/scion/go/sig/disp"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/ingress"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/xnet"
)

var sighup chan os.Signal

func init() {
	sighup = make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
}

var (
	id      = flag.String("id", "", "Element ID (Required. E.g. 'sig4-21-9')")
	cfgPath = flag.String("config", "", "Config file (Required)")
	isdas   = flag.String("ia", "", "Local AS (Required, e.g., 1-10)")
	ipStr   = flag.String("ip", "", "address to bind to (Required)")
)

func main() {
	liblog.AddDefaultLogFlags()
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		flag.Usage()
		os.Exit(1)
	}
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	setupSignals()
	if err := checkPerms(); err != nil {
		fatal("Permissions checks failed", "err", err)
	}

	// Export prometheus metrics.
	metrics.Init(*id)
	if err := metrics.Start(); err != nil {
		fatal("Unable to export prometheus metrics", "err", err)
	}
	// Parse basic flags
	ia, err := addr.IAFromString(*isdas)
	if err != nil {
		fatal("Unable to parse local ISD-AS", "ia", *isdas, "err", err)
	}
	ip := net.ParseIP(*ipStr)
	if ip == nil {
		fatal("unable to parse IP address", "addr", *ipStr)
	}
	if err = sigcmn.Init(ia, ip); err != nil {
		fatal("Error during initialization", "err", err)
	}
	tunIO, err := setupTun()
	if err != nil {
		fatal("Unable to create & configure TUN device", "err", err)
	}
	egress.Init()
	disp.Init(sigcmn.CtrlConn)
	go base.PollReqHdlr()
	// Parse config
	if loadConfig(*cfgPath) != true {
		fatal("Unable to load config on startup")
	}
	go reloadOnSIGHUP(*cfgPath)
	// Spawn egress reader
	go egress.NewReader(tunIO).Run()
	// Spawn ingress Dispatcher.
	if err := ingress.Init(tunIO); err != nil {
		fatal("Unable to spawn ingress dispatcher", "err", err)
	}
}

func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		liblog.Flush()
		os.Exit(1)
	}()
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
	if !caps.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {
		return common.NewBasicError("CAP_NET_ADMIN is required", nil, "caps", caps)
	}
	return nil
}

func setupTun() (io.ReadWriteCloser, error) {
	tunLink, tunIO, err := xnet.ConnectTun(*sigcmn.SigTun)
	if err != nil {
		return nil, err
	}
	if err = xnet.AddRoute(tunLink, sigcmn.DefV4Net); err != nil {
		return nil,
			common.NewBasicError("Unable to add default IPv4 route to SIG routing table", err)
	}
	if err = xnet.AddRoute(tunLink, sigcmn.DefV6Net); err != nil {
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

func reloadOnSIGHUP(path string) {
	defer liblog.LogPanicAndExit()
	log.Info("reloadOnSIGHUP: started")
	for range sighup {
		log.Info("reloadOnSIGHUP: reloading...")
		success := loadConfig(path)
		// Errors already logged in loadConfig
		log.Info("reloadOnSIGHUP: reload done", "success", success)
	}
	log.Info("reloadOnSIGHUP: stopped")
}

func loadConfig(path string) bool {
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		log.Error("loadConfig: Failed", "err", err)
		return false
	}
	ok := base.Map.ReloadConfig(cfg)
	if ok {
		atomic.StoreUint64(&metrics.ConfigVersion, cfg.ConfigVersion)
	}
	return ok
}

func fatal(msg string, args ...interface{}) {
	log.Crit(msg, args...)
	liblog.Flush()
	os.Exit(1)
}
