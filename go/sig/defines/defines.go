package defines

import (
	"io"
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

type Global struct {
	Config          string
	SCIOND          *sciond.Connector
	IA              *addr.ISD_AS
	Silent          bool
	Encapsulation   string
	InternalIngress io.ReadWriteCloser

	Port uint16
	Addr addr.HostAddr

	ExternalIngress net.Conn
	ExternalEgress  net.Conn
	DispatcherPath  string
}
