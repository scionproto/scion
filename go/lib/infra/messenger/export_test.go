package messenger

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/svc"
)

func (r AddressRewriter) BuildFullAddress(ctx context.Context, a net.Addr) (*snet.Addr, error) {
	return r.buildFullAddress(ctx, a)
}

func (r AddressRewriter) ResolveIfSVC(ctx context.Context, p snet.Path,
	a *addr.AppAddr) (snet.Path, *addr.AppAddr, bool, error) {
	return r.resolveIfSVC(ctx, p, a)
}

func ParseReply(reply *svc.Reply) (*addr.AppAddr, error) {
	return parseReply(reply)
}
