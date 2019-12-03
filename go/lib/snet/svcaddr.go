package snet

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/spath"
)

// SVCAddr is the address type for SVC destinations.
type SVCAddr struct {
	Addr

	SVC addr.HostSVC
}

// NewSVCAddr returns a new instance of SVCAddr.
// TODO(karampok). constructor to be removed once snet.Addr is removed.
func NewSVCAddr(ia addr.IA, p *spath.Path, nh *net.UDPAddr, svc addr.HostSVC) *SVCAddr {
	a := newAddr(ia, p, nh)
	return &SVCAddr{*a, svc}
}

// Network implements net.Addr interface.
func (a *SVCAddr) Network() string {
	return "scion"
}

// String implements net.Addr interface.
func (a *SVCAddr) String() string {
	return fmt.Sprintf("%v,%v", a.IA, a.SVC)
}

// ToAddr returns a legacy snet.Addr.
func (a *SVCAddr) ToAddr() *Addr {
	ret := &Addr{
		IA:      a.IA,
		NextHop: CopyUDPAddr(a.NextHop),
		Host:    &addr.AppAddr{L3: a.SVC},
	}
	if a.Path != nil {
		ret.Path = a.Path.Copy()
	}
	return ret

}
