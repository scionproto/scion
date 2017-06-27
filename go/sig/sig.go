package main

import (
	"flag"
	"net"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/defines"
	"github.com/netsec-ethz/scion/go/sig/management"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	Version             = "0.0.1"
	InternalIngressName = "scion.local"
	ExternalIngressPort = 10080
)

func main() {
	var config = flag.String("config", "", "optional config file")
	var sciondPath = flag.String("sciond", "/run/shm/sciond.sock", "SCIOND socket path")
	var dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock", "SCION Dispatcher path")
	var isdas = flag.String("isdas", "", "Local AS (in ISD-AS format, e.g., 1-10)")
	var silent = flag.Bool("silent", false, "disable interactive console")
	var encapsulation = flag.String("encap", "ip", "encapsulation type, either ip or scion")
	var ip = flag.String("ip", "", "public IP address of the SIG")
	var port = flag.Int("port", 10080, "public port for ingress data")
	flag.Parse()

	// Parse arguments and connect to relevant services
	var err error
	var cerr *common.Error

	global := &defines.Global{}
	global.DispatcherPath = *dispatcherPath
	global.Config = *config
	global.Silent = *silent

	switch *encapsulation {
	case "ip":
		global.Encapsulation = "ip"
		global.SCIOND = nil
		global.IA = nil

		global.ExternalIngress, err = xnet.OpenUDP(ExternalIngressPort)
		if err != nil {
			log.Crit("Unable to open ingress port", "port", ExternalIngressPort, "err", err)
			return
		}

		global.ExternalEgress = nil
	case "scion":
		global.Encapsulation = "scion"
		global.SCIOND, err = sciond.Connect(*sciondPath)
		if err != nil {
			log.Crit("Unable to connect to SCIOND", "path", *sciondPath)
			return
		}
		global.IA, cerr = addr.IAFromString(*isdas)
		if cerr != nil {
			log.Crit("Unable to parse local AS", "isdas", *isdas)
			return
		}

		netip := net.ParseIP(*ip)
		if netip == nil {
			log.Crit("Unable to parse public address", "addr", *ip)
			return
		}
		global.Addr = addr.HostFromIP(netip)

		global.Port = uint16(*port)
		if global.Port < 0 || global.Port > 65535 {
			log.Crit("Invalid port number", "port", global.Port)
			return
		}

		a := reliable.AppAddr{Addr: global.Addr, Port: global.Port}

		global.ExternalIngress, _, err = reliable.Register(*dispatcherPath, global.IA, a)
		if err != nil {
			log.Crit("Unable to register with dispatcher", "dispatcher", *dispatcherPath,
				"IA", global.IA, "addr", a, "err", err)
			return
		}
	default:
		log.Crit("Unknown encapsulation", "encapsulation", *encapsulation)
		return
	}

	global.InternalIngress, err = xnet.ConnectTun(InternalIngressName)
	if err != nil {
		log.Crit("Unable to open local TUN interface", "name", InternalIngressName, "err", err)
		return
	}

	// Create main SIG table
	sdb, err := base.NewSDB(global)
	if err != nil {
		log.Error("Failed to create SDB", "err", err)
		return
	}

	// Enable static routing
	static := control.Static(sdb)

	// Launch data plane receiver
	go base.IngressWorker(global)

	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(Version, static, global.Config)
	}
	if *silent == true {
		// Block forever
		select {}
	}
	management.Run(Version, static)
}
