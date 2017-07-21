package base

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/lib/scion"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

type asInfo struct {
	sync.RWMutex
	Name       string
	IA         *addr.ISD_AS
	sigs       map[string]net.Conn
	Subnets    map[string]*net.IPNet
	DeviceName string
	Device     io.ReadWriteCloser
	scionNet   *scion.SCIONNet
}

// newASInfo initializes the internal structures and creates the tunnel
// interface for a new remote AS.
func newASInfo(scionNet *scion.SCIONNet, isdas string) (*asInfo, error) {
	var err error
	ia, cerr := addr.IAFromString(isdas)
	if cerr != nil {
		return nil, cerr
	}
	info := &asInfo{
		Name:       isdas,
		IA:         ia,
		sigs:       make(map[string]net.Conn),
		Subnets:    make(map[string]*net.IPNet),
		DeviceName: fmt.Sprintf("scion.%s", isdas),
		scionNet:   scionNet,
	}
	if info.Device, err = xnet.ConnectTun(info.DeviceName); err != nil {
		return nil, err
	}
	return info, nil
}

func (as *asInfo) addRoute(subnet *net.IPNet) error {
	as.Lock()
	defer as.Unlock()
	subnetKey := subnet.String()
	if _, found := as.Subnets[subnetKey]; found {
		return common.NewError("Subnet already exists", "subnet", subnet)
	}
	as.Subnets[subnetKey] = subnet
	return nil
}

func (as *asInfo) delRoute(subnet *net.IPNet) error {
	as.Lock()
	defer as.Unlock()
	subnetKey := subnet.String()
	if _, found := as.Subnets[subnetKey]; !found {
		return common.NewError("Subnet not found", "subnet", subnet)
	}
	delete(as.Subnets, subnetKey)
	return nil
}

func (as *asInfo) addSig(encapAddr string, encapPort string, ctrlAddr string,
	ctrlPort string, source string) error {
	as.Lock()
	defer as.Unlock()

	sig := fmt.Sprintf("[%s]:%d", encapAddr, encapPort)
	if _, found := as.sigs[sig]; found {
		return common.NewError("SIG entry exists", "sig", sig)
	}
	ip := net.ParseIP(encapAddr)
	if ip == nil {
		return common.NewError("Unable to parse IP address", "address", encapAddr)
	}
	nport, err := strconv.ParseUint(encapPort, 10, 16)
	if err != nil {
		return common.NewError("Unable to parse port", "port", encapPort, "err", err)
	}

	var conn net.Conn
	conn, err = as.scionNet.DialSCION(as.IA, addr.HostFromIP(net.IPv4zero),
		addr.HostFromIP(ip), uint16(nport))
	if err != nil {
		return common.NewError("Unable to establish flow", "err", err)
	}

	as.sigs[sig] = conn
	// Register with keepalive module
	/*
		remote := hello.Remote{
			IA:      as.IA,
			Address: ctrlAddr,
			Port:    ctrlPort,
			OnDown:  func() { log.Debug("OnDown") },
			OnUp:    func() { log.Debug("OnUp") },
			OnError: func() { log.Debug("OnError") }}
		err = as.SDB.helloModule.Register(&remote)
		if err != nil {
			return common.NewError("Unable to Register", "err", err)
		}
	*/
	return nil
}

func (as *asInfo) delSig(address string, port string, source string) error {
	return common.NewError("NotImplemented", "function", "delSig")
}

func (as *asInfo) getConn() (net.Conn, error) {
	as.RLock()
	defer as.RUnlock()

	//FIXME(scrye): inspect SIG state during selection once keepalive module is included
	for _, v := range as.sigs {
		return v, nil
	}
	return nil, common.NewError("SIG not found", "DstIA", as.IA)
}

func (as *asInfo) String() string {
	as.RLock()
	defer as.RUnlock()

	output := fmt.Sprintf("ISDAS %v:\n", as.IA)
	output += "  SIGs:\n"
	if len(as.sigs) == 0 {
		output += fmt.Sprintf("    (no SIGs)\n")
	}
	for sig, _ := range as.sigs {
		output += "    " + sig + "\n"
	}
	output += "Prefixes:\n"
	if len(as.Subnets) == 0 {
		output += fmt.Sprintf("    (no prefixes)\n")
	}
	for subnet, _ := range as.Subnets {
		output += "    " + subnet + "\n"
	}
	return output
}
