package global

import (
	"io"
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
)

const (
	Version             = "0.1.0"
	InternalIngressName = "scion.local"
	ExternalIngressPort = 10080
	DefaultCtrlIP       = "0.0.0.0"
	DefaultCtrlPort     = 10081
)

var (
	Config        string
	Silent        bool
	Encapsulation string

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
