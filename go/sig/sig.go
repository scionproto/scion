package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/global"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/management"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

func main() {
	var config = flag.String("config", "", "optional config file")
	var sciondPath = flag.String("sciond", "/run/shm/sciond.sock", "SCIOND socket path")
	var dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock", "SCION Dispatcher path")
	var isdas = flag.String("isdas", "", "Local AS (in ISD-AS format, e.g., 1-10)")
	var cli = flag.Bool("cli", false, "enable interactive console")
	var ip = flag.String("encapip", "", "encapsulation data bind address")
	var port = flag.Int("encapport", global.ExternalIngressPort, "encapsulation data port")
	var ctrlIP = flag.String("ctrlip", "", "control data bind address")
	var ctrlPort = flag.Int("ctrlport", global.DefaultCtrlPort, "control data port (e.g., keepalives)")
	flag.Parse()

	liblog.Setup("sig")
	setupSignals()

	// Parse arguments and connect to relevant services
	var err error
	var cerr *common.Error

	global.Config = *config
	global.ConsoleEnabled = *cli
	if global.Config == "" && global.ConsoleEnabled == false {
		log.Crit("Unable to start SIG without initial config and without interactive console.")
		os.Exit(1)
	}

	global.IA, cerr = addr.IAFromString(*isdas)
	if cerr != nil {
		log.Crit("Unable to parse local AS", "isdas", *isdas)
		os.Exit(1)
	}

	netip := net.ParseIP(*ip)
	if netip == nil {
		log.Crit("Unable to parse public address", "addr", *ip)
		os.Exit(1)
	}
	global.Addr = addr.HostFromIP(netip)
	global.Port = uint16(*port)
	if global.Port == 0 {
		log.Crit("Invalid port number", "port", global.Port)
		os.Exit(1)
	}

	global.CtrlIP = net.ParseIP(*ctrlIP)
	if global.CtrlIP == nil {
		log.Crit("Unable to parse bind IP address for control traffic", "address", *ctrlIP)
		os.Exit(1)
	}
	global.CtrlPort = uint16(*ctrlPort)
	if global.CtrlPort == 0 {
		log.Crit("Invalid port number", "port", global.CtrlPort)
		os.Exit(1)
	}

	global.DispatcherPath = *dispatcherPath
	global.Context, err = scion.NewContext(global.IA, *sciondPath, global.DispatcherPath)
	if err != nil {
		log.Crit("Unable to initialize local SCION context", "err", err)
		os.Exit(1)
	}
	global.ExternalIngress, err = global.Context.ListenSCION(global.Addr, global.Port)
	if err != nil {
		log.Crit("Unable to listen on SCION address", "addr", global.Addr, "port", global.Port)
		os.Exit(1)
	}
	global.InternalIngress, err = xnet.ConnectTun(global.InternalIngressName)
	if err != nil {
		log.Crit("Unable to open local TUN interface", "name", global.InternalIngressName, "err", err)
		os.Exit(1)
	}

	sdb, err := base.NewSDB()
	if err != nil {
		log.Error("Failed to create SDB", "err", err)
		os.Exit(1)
	}
	// Enable static routing
	static := control.Static(sdb)
	// Launch data plane receiver
	go base.IngressWorker()

	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(static, global.Config)
	}
	if global.ConsoleEnabled == false {
		// Block forever
		select {}
	} else {
		management.Run(static)
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
