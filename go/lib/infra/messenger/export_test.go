package messenger

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc"
)

func (r AddressRewriter) BuildFullAddress(ctx context.Context,
	a *snet.SVCAddr) (*snet.SVCAddr, error) {
	return r.buildFullAddress(ctx, a)
}

func (r AddressRewriter) ResolveSVC(ctx context.Context, p snet.Path,
	s addr.HostSVC) (snet.Path, *net.UDPAddr, bool, error) {
	return r.resolveSVC(ctx, p, s)
}

func ParseReply(reply *svc.Reply) (*net.UDPAddr, error) {
	return parseReply(reply)
}
