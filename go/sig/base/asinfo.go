package base

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/global"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

type asInfo struct {
	Name string
	IA   *addr.ISD_AS
	SDB  *SDB
	sigs map[string]net.Conn

	// NOTE(scrye): A map would probably be a better fit for subnets
	Subnets *list.List

	Device     io.ReadWriteCloser
	DeviceName string

	lock sync.Mutex
}

// newASInfo initializes the internal structures and creates the tunnel interface for a new remote AS.
func newASInfo(sdb *SDB, isdas string) (*asInfo, error) {
	var err error
	info := new(asInfo)
	info.DeviceName = fmt.Sprintf("scion.%s", isdas)

	ia, nerr := addr.IAFromString(isdas)
	if nerr != nil {
		return nil, nerr
	}
	info.IA = ia
	info.SDB = sdb
	info.sigs = make(map[string]net.Conn)

	// Create tunnel interface for this AS
	info.Device, err = xnet.ConnectTun(info.DeviceName)
	if err != nil {
		return nil, err
	}

	info.Name = isdas
	info.Subnets = list.New()

	return info, nil
}

func (as *asInfo) addRoute(subnet *net.IPNet) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	for e := as.Subnets.Front(); e != nil; e = e.Next() {
		network := e.Value.(*net.IPNet)
		if bytes.Equal(network.IP, subnet.IP) && bytes.Equal(network.Mask, subnet.Mask) {
			return common.NewError("Subnet exists", "subnet", subnet)
		}
	}
	as.Subnets.PushBack(subnet)
	return nil
}

func (as *asInfo) delRoute(subnet *net.IPNet) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	for e := as.Subnets.Front(); e != nil; e = e.Next() {
		network := e.Value.(*net.IPNet)
		if bytes.Equal(network.IP, subnet.IP) && bytes.Equal(network.Mask, subnet.Mask) {
			as.Subnets.Remove(e)
		}
	}
	return common.NewError("Subnet not found", "subnet", subnet)
}

func (as *asInfo) addSig(encapAddr string, encapPort string, ctrlAddr string, ctrlPort string, source string) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	sig := encapAddr + ":" + encapPort
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
	switch global.Encapsulation {
	case "ip":
		remote := &net.UDPAddr{IP: ip, Port: int(nport)}
		conn, err = net.DialUDP("udp", nil, remote)
		if err != nil {
			return common.NewError("Unable to establish flow", "err", err)
		}
	case "scion":
		conn, err = global.Context.DialSCION(as.IA, addr.HostFromIP(ip), uint16(nport))
		if err != nil {
			return common.NewError("Unable to establish flow", "err", err)
		}
	default:
		return common.NewError("Unknown encapsulation", "encapsulation", global.Encapsulation)
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
	as.lock.Lock()
	defer as.lock.Unlock()

	// Just grab one
	for _, v := range as.sigs {
		return v, nil
	}
	return nil, common.NewError("SIG not found", "DstIA", as.IA)
}
