package scion

import (
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/sciond"
)

// SCIONAppAddr implements net.Addr
type SCIONAppAddr struct {
	ia   *addr.ISD_AS
	host addr.HostAddr
	port uint16
	path sciond.PathReplyEntry
}

func (sa *SCIONAppAddr) Network() string {
	return "scion"
}

func (sa *SCIONAppAddr) String() string {
	return fmt.Sprintf("%v,%v,%v,%x", sa.ia, sa.host, sa.port, sa.path)
}
