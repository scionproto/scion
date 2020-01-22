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
	var ip net.IP
	var port int
	if a.Host == nil {
		ip = nil
		port = 0
	} else {
		ip = a.Host.IP
		port = a.Host.Port
	}
	return fmt.Sprintf("%v,[%v]:%v", a.IA, ip, port)
}

// Set implements the flag.Value interface
func (a *UDPAddr) Set(s string) error {
	other, err := AddrFromString(s)
	if err != nil {
		return err
	}
	*a = *other.ToXAddr().(*UDPAddr)
	return nil
}
