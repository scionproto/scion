package main

import (
	"flag"
	"net"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
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
	var silent = flag.Bool("silent", false, "disable interactive console")
	var encapsulation = flag.String("encap", "ip", "encapsulation type, either ip or scion")
	var ip = flag.String("ip", "", "public IP address of the SIG")
	var port = flag.Int("port", 10080, "public port for ingress data")
	flag.Parse()

	// Parse arguments and connect to relevant services
	var err error
	var cerr *common.Error
	global.DispatcherPath = *dispatcherPath
	global.Config = *config
	global.Silent = *silent
	global.CtrlIP = net.ParseIP(global.DefaultCtrlIP)
	if global.CtrlIP == nil {
		log.Crit("Unable to parse bind IP address for control traffic", "address", global.DefaultCtrlIP)
		return
	}
	global.CtrlPort = global.DefaultCtrlPort

	switch *encapsulation {
	case "ip":
		global.Encapsulation = "ip"
		global.SCIOND = nil
		global.IA = nil
		global.ExternalIngress, err = xnet.OpenUDP(global.ExternalIngressPort)
		if err != nil {
			log.Crit("Unable to open ingress port", "port", global.ExternalIngressPort, "err", err)
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

		global.Context, err = scion.NewContext(global.IA, *sciondPath, global.DispatcherPath)
		if err != nil {
			log.Crit("Unable to initialize local SCION context", "err", err)
			return
		}

		global.Port = uint16(*port)
		if global.Port == 0 {
			log.Crit("Invalid port number", "port", global.Port)
			return
		}

		global.ExternalIngress, err = global.Context.ListenSCION(global.Addr, global.Port)
		if err != nil {
			log.Crit("Unable to listen on SCION address", "addr", global.Addr, "port", global.Port)
			return
		}
	default:
		log.Crit("Unknown encapsulation", "encapsulation", *encapsulation)
		return
	}

	global.InternalIngress, err = xnet.ConnectTun(global.InternalIngressName)
	if err != nil {
		log.Crit("Unable to open local TUN interface", "name", global.InternalIngressName, "err", err)
		return
	}

	sdb, err := base.NewSDB()
	if err != nil {
		log.Error("Failed to create SDB", "err", err)
		return
	}

	// Enable static routing
	static := control.Static(sdb)

	// Launch data plane receiver
	go base.IngressWorker()

	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(static, global.Config)
	}
	if *silent == true {
		// Block forever
		select {}
	}
	management.Run(static)
}
