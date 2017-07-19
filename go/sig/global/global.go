package global

import (
	"flag"
	"io"
	"net"
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const (
	Version             = "0.1.0"
	InternalIngressName = "scion.local"
	ExternalIngressPort = 10080
	DefaultCtrlPort     = 10081
)

var (
	Config         string
	ConsoleEnabled bool

	Context *scion.Context
	IA      *addr.ISD_AS
	Addr    addr.HostAddr
	Port    uint16

	DispatcherPath  string
	SCIOND          *sciond.Connector
	InternalIngress io.ReadWriteCloser
	ExternalIngress net.Conn
	ExternalEgress  net.Conn

	CtrlIP   net.IP
	CtrlPort uint16
)

var (
	sciondPath     = flag.String("sciond", "/run/shm/sciond.sock", "SCIOND socket path")
	dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock", "SCION Dispatcher path")
	isdas          = flag.String("isdas", "", "Local AS (in ISD-AS format, e.g., 1-10)")
	ip             = flag.String("encapip", "", "encapsulation data bind address")
	port           = flag.Int("encapport", ExternalIngressPort, "encapsulation data port")
	ctrlIP         = flag.String("ctrlip", "", "control data bind address (if missing, defaults to -ip arg)")
	ctrlPort       = flag.Int("ctrlport", DefaultCtrlPort, "control data port (e.g., keepalives)")
)

func parseEncapAddress() {
	var cerr *common.Error
	IA, cerr = addr.IAFromString(*isdas)
	if cerr != nil {
		log.Crit("Unable to parse local AS", "isdas", *isdas)
		os.Exit(1)
	}
	netip := net.ParseIP(*ip)
	if netip == nil {
		log.Crit("Unable to parse public address", "addr", *ip)
		os.Exit(1)
	}
	Addr = addr.HostFromIP(netip)
	Port = uint16(*port)
	if Port == 0 {
		log.Crit("Invalid port number", "port", Port)
		os.Exit(1)
	}
}

func parseCtrlAddress() {
	if *ctrlIP == "" {
		// Default to encapip
		*ctrlIP = *ip
	}
	CtrlIP = net.ParseIP(*ctrlIP)
	if CtrlIP == nil {
		log.Crit("Unable to parse bind IP address for control traffic", "address", *ctrlIP)
		os.Exit(1)
	}
	CtrlPort = uint16(*ctrlPort)
	if CtrlPort == 0 {
		log.Crit("Invalid port number", "port", CtrlPort)
		os.Exit(1)
	}
}

func initDispatcher() {
	var err error
	DispatcherPath = *dispatcherPath
	Context, err = scion.NewContext(IA, *sciondPath, DispatcherPath)
	if err != nil {
		log.Crit("Unable to initialize local SCION context", "err", err)
		os.Exit(1)
	}
}

func initInterfaces() {
	var err error
	ExternalIngress, err = Context.ListenSCION(Addr, Port)
	if err != nil {
		log.Crit("Unable to listen on SCION address", "addr", Addr, "port", Port)
		os.Exit(1)
	}
	InternalIngress, err = xnet.ConnectTun(InternalIngressName)
	if err != nil {
		log.Crit("Unable to open local TUN interface", "name", InternalIngressName, "err", err)
		os.Exit(1)
	}
}

func Init() {
	parseEncapAddress()
	parseCtrlAddress()
	initDispatcher()
	initInterfaces()
}
