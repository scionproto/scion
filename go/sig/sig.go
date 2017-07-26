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
	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/management"
	"github.com/netsec-ethz/scion/go/sig/metrics"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	DefaultCtrlPort     = 10081
	ExternalIngressPort = 10080
)

var (
	Addr     addr.HostAddr
	Port     uint16
	CtrlIP   net.IP
	CtrlPort uint16
)

var (
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
	liblog.Setup("sig")
	defer liblog.PanicLog()
	setupSignals()

	// Export prometheus metrics.
	if err := metrics.Start(); err != nil {
		log.Error("Unable to export prometheus metrics", "err", err)
	}

	ia, cerr := addr.IAFromString(*isdas)
	if cerr != nil {
		log.Error("Unable to parse local AS", "isdas", *isdas, "err", cerr)
		os.Exit(1)
	}

	// Initialize SCION local networking module
	scionNet, err := scion.NewSCIONNet(ia, *sciondPath, *dispatcherPath)
	if err != nil {
		log.Error("Unable to create local SCION Network context", "err", err)
		os.Exit(1)
	}

	// Create tables for managing remote AS information and spawning data plane senders
	topology, err := base.NewTopology(scionNet)
	if err != nil {
		log.Error("Unable to create topology", "err", err)
		os.Exit(1)
	}

	// Spawn data plane receiver
	err = parseEncapFlags()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	iw := base.NewIngressWorker(scionNet, Addr, Port)
	go iw.Run()

	// TODO(scrye): Launch keepalive module
	/*
		err = parseCtrlFlags()
		if err != nil {
			log.Error(err.Error())
			os.Exit(1)
		}
	*/

	// Enable static routing
	static := control.NewStaticRP(topology)
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

func parseEncapFlags() error {
	netip := net.ParseIP(*ip)
	if netip == nil {
		return common.NewError("Unable to parse encapsulation IP address", "addr", *ip)
	}
	xnet.Setup(netip)
	Addr = addr.HostFromIP(netip)
	Port = uint16(*port)
	if Port == 0 {
		return common.NewError("Invalid port number", "port", Port)
	}
	return nil
}

func parseCtrlFlags() error {
	if *ctrlIP == "" {
		// Default to encapip
		*ctrlIP = *ip
	}
	CtrlIP = net.ParseIP(*ctrlIP)
	if CtrlIP == nil {
		return common.NewError("Unable to parse bind IP address for control traffic",
			"address", *ctrlIP)
	}
	CtrlPort = uint16(*ctrlPort)
	if CtrlPort == 0 {
		return common.NewError("Invalid port number", "port", Port)
	}
	return nil
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
