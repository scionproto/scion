package snetutils

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/internal"
)

// NewSnetAddr returns a uninitialized Addr
func NewEmptySnetAddr() snet.Addr {
	return &internal.Addr{}
}

func NewSnetAddr(ia addr.IA, host addr.HostAddr, port uint16) snet.Addr {
	return &internal.Addr{IA: ia, Host: host, L4Port: port}
}

var (
	// DefNetwork is the default networking context
	DefNetwork *internal.Network
)

const (
	UninitializedSCIONNetwork        = "SCION Network not initialized"
	UnableToReinitializeSCIONNetwork = "Cannot initialize global SCION network twice"
)

// Init initializes the default SCION networking context.
func Init(ia addr.IA, sciondPath string, dispatcherPath string) error {
	network, err := internal.NewNetwork(ia, sciondPath, dispatcherPath)
	if err != nil {
		return err
	}
	return initWithNetwork(network)
}

func initWithNetwork(network *internal.Network) error {
	if DefNetwork != nil {
		return common.NewBasicError(UnableToReinitializeSCIONNetwork, nil)
	}
	DefNetwork = network
	return nil
}

// IA return local IA for the default networking context.
func IA() addr.IA {
	if DefNetwork == nil {
		return addr.IA{}
	}
	return DefNetwork.IA()
}

// DialSCION calls DialSCION on the default networking context.
func DialSCION(network string, laddr, raddr snet.Addr) (snet.Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError(UninitializedSCIONNetwork, nil)
	}
	return DefNetwork.DialSCION(network, laddr.(*internal.Addr), raddr.(*internal.Addr))
}

// DialSCIONWithSVC calls DialSCIONWithSVC on the default networking context.
func DialSCIONWithBindSVC(network string, laddr, raddr, baddr snet.Addr,
	svc addr.HostSVC) (snet.Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError(UninitializedSCIONNetwork, nil)
	}
	return DefNetwork.DialSCIONWithBindSVC(network, laddr.(*internal.Addr), raddr.(*internal.Addr),
		baddr.(*internal.Addr), svc)
}

// ListenSCION calls ListenSCION on the default networking context.
func ListenSCION(network string, laddr snet.Addr) (snet.Conn, error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError(UninitializedSCIONNetwork, nil)
	}
	return DefNetwork.ListenSCION(network, laddr.(*internal.Addr))
}

// ListenSCIONWithBindSVC calls ListenSCIONWithBindSVC on the default networking context.
func ListenSCIONWithBindSVC(network string, laddr, baddr snet.Addr, svc addr.HostSVC) (snet.Conn,
	error) {
	if DefNetwork == nil {
		return nil, common.NewBasicError(UninitializedSCIONNetwork, nil)
	}
	return DefNetwork.ListenSCION(network, laddr.(*internal.Addr))
}
