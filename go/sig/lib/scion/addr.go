package scion

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// SCIONAddr implements net.Addr
type SCIONAddr struct {
	ia   *addr.ISD_AS
	host addr.HostAddr
	port uint16
	path sciond.PathReplyEntry
}

func (sa *SCIONAddr) Network() string {
	return "scion"
}

func (sa *SCIONAddr) String() string {
	return fmt.Sprintf("%v,%v,%v,%x", sa.ia, sa.host, sa.port, sa.path)
}
