package snet

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/spath"
)

// UDPAddr to be used when UDP host.
type UDPAddr struct {
	Addr

	Host *net.UDPAddr
}

// NewUDPAddr returns an instance of UDPAddr.
// TODO(karampok). constructor to be removed once snet.Addr is removed.
func NewUDPAddr(ia addr.IA, p *spath.Path, nh *net.UDPAddr, t *net.UDPAddr) *UDPAddr {
	a := newAddr(ia, p, nh)
	return &UDPAddr{*a, t}
}

// Network implements net.Addr interface.
func (a *UDPAddr) Network() string {
	return "scion"
}

// String implements net.Addr interface.
func (a *UDPAddr) String() string {
	return fmt.Sprintf("%v,[%v]:%v", a.IA, a.Host.IP, a.Host.Port)
}

// ToAddr returns a legacy snet.Addr.
func (a *UDPAddr) ToAddr() *Addr {
	ret := &Addr{
		IA:      a.IA,
		NextHop: CopyUDPAddr(a.NextHop),
		Host: &addr.AppAddr{
			L3: addr.HostFromIP(a.Host.IP),
			L4: uint16(a.Host.Port),
		},
	}
	if a.Path != nil {
		ret.Path = a.Path.Copy()
	}
	return ret

}
