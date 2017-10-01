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
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/ingress"
	"github.com/netsec-ethz/scion/go/sig/management"
	"github.com/netsec-ethz/scion/go/sig/metrics"
)

const (
	DefaultCtrlPort     = 10081
	ExternalIngressPort = 10080
)

var (
	id             = flag.String("id", "", "Element ID (Required. E.g. 'sig4-21-9')")
	config         = flag.String("config", "", "optional config file")
	cli            = flag.Bool("cli", false, "enable interactive console")
	port           = flag.Int("encapport", ExternalIngressPort, "encapsulation data port")
	ip             = flag.String("encapip", "", "encapsulation data bind address")
	ctrlIP         = flag.String("ctrlip", "", "control data bind address (if missing, defaults to -ip arg)")
	ctrlPort       = flag.Int("ctrlport", DefaultCtrlPort, "control data port (e.g., keepalives)")
	sciondPath     = flag.String("sciond", "/run/shm/sciond/sciond.sock", "SCIOND socket path")
	dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock", "SCION Dispatcher path")
	isdas          = flag.String("isdas", "", "Local AS (in ISD-AS format, e.g., 1-10)")
)

func main() {
	flag.Parse()
	if *id == "" {
		log.Crit("No element ID specified")
		os.Exit(1)
	}
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	setupSignals()

	// Export prometheus metrics.
	metrics.Init(*id)
	if err := metrics.Start(); err != nil {
		log.Error("Unable to export prometheus metrics", "err", err)
	}

	ia, err := addr.IAFromString(*isdas)
	if err != nil {
		fatal("Unable to parse local ISD-AS", "ia", isdas, "err", err)
	}

	// Initialize SCION local networking module
	err = snet.Init(ia, *sciondPath, *dispatcherPath)
	if err != nil {
		fatal("Unable to create local SCION Network context", "err", err)
	}

	localEncapAddr, err := parseFlagAddr(ia, *ip, *port)
	if err != nil {
		fatal("Unable to parse local encap address", "err", err)
	}

	if *ctrlIP == "" {
		*ctrlIP = *ip
	}
	localCtrlAddr, err := parseFlagAddr(ia, *ctrlIP, *ctrlPort)
	if err != nil {
		fatal("Unable to parse local control address", "err", err)
	}

	// Initialize SIG information tables
	err = base.Init(localCtrlAddr, localEncapAddr)
	if err != nil {
		fatal("Unable to initialize tables", "err", err)
	}

	// Spawn ingress Dispatcher.
	if err := ingress.NewDispatcher(localEncapAddr).Run(); err != nil {
		fatal("Unable to spawn ingress dispatcher", "err", err)
	}

	// Enable static routing
	static := control.NewStaticRP()
	// Load configuration file and/or start interactive console
	setupManagement(static)
	// If no console is up, block forever
	if *cli == false {
		select {}
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

func parseFlagAddr(ia *addr.ISD_AS, ipStr string, port int) (*snet.Addr, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, common.NewCError("unable to parse IP address", "addr", ipStr)
	}
	if port == 0 || port >= (1<<16) {
		return nil, common.NewCError("invalid port number", "port", port)
	}
	address := &snet.Addr{
		IA:     ia,
		Host:   addr.HostFromIP(ip),
		L4Port: uint16(port),
	}
	return address, nil
}

func setupManagement(static *control.StaticRP) {
	if *config == "" && *cli == false {
		log.Crit("Unable to start SIG without initial config and interactive console.")
		os.Exit(1)
	}
	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(static, *config)
	}
	if *cli {
		management.Run(static)
	}
}

func fatal(msg string, args ...interface{}) {
	log.Crit(msg, args...)
	liblog.Flush()
	os.Exit(1)
}
