package base

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

type SigEndpoint struct {
	IP   net.IP
	Port uint16

	Conn   *net.UDPConn
	Source string

	TX    uint
	RX    uint
	PktTX uint
	PktRX uint
}

type ASInfo struct {
	Name string
	SDB  *SDB
	sigs []*SigEndpoint
	// NOTE(scrye): A map would probably be a better fit for subnets
	Subnets *list.List

	Device     io.ReadWriteCloser
	DeviceName string

	lock sync.Mutex
}

// NewASInfo initializes the internal structures and creates the tunnel interface for a new remote AS.
func NewASInfo(isdas string) (*ASInfo, error) {
	var err error
	info := new(ASInfo)
	info.DeviceName = fmt.Sprintf("scion.%s", isdas)

	// Create tunnel interface for this AS
	info.Device, err = xnet.ConnectTun(info.DeviceName)
	if err != nil {
		return nil, err
	}
	info.sigs = make([]*SigEndpoint, 0, 4)
	info.Name = isdas
	info.Subnets = list.New()

	return info, nil
}

func (as *ASInfo) findSig(address string, port string) (int, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return -1, common.NewError("Unable to parse IP address", "address", address)
	}

	nport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return -1, err
	}

	for i, e := range as.sigs {
		if bytes.Compare(e.IP, ip) == 0 && e.Port == uint16(nport) {
			return i, nil
		}
	}
	return -1, nil
}

func (as *ASInfo) AddRoute(subnet *net.IPNet) error {
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

func (as *ASInfo) DelRoute(subnet *net.IPNet) error {
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

func (as *ASInfo) AddSig(address string, port string, source string) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	ip := net.ParseIP(address)
	if ip == nil {
		return common.NewError("Unable to parse IP address", "address", address)
	}

	nport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return err
	}

	// Check if the entry exists
	index, err := as.findSig(address, port)
	if err != nil {
		return err
	}
	if index != -1 {
		return common.NewError("SIG entry exists", "address", address, "port", port)
	}

	// Check if we have space
	if len(as.sigs) == cap(as.sigs) {
		return common.NewError("Unable to add SIG, limit reached", "limit", cap(as.sigs))
	}

	remote := &net.UDPAddr{IP: ip, Port: int(nport)}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return err
	}

	as.sigs = append(as.sigs, &SigEndpoint{IP: ip, Port: uint16(nport), Conn: conn})
	return nil
}

func (as *ASInfo) DelSig(address string, port string, source string) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	// Check if the entry exists
	index, err := as.findSig(address, port)
	if err != nil {
		return err
	}
	if index == -1 {
		return common.NewError("SIG entry not found", "address", address, "port", port)
	}

	// Shift over deleted entry
	copy(as.sigs[index:len(as.sigs)-1], as.sigs[index+1:len(as.sigs)])
	as.sigs = as.sigs[0 : len(as.sigs)-1]
	return nil
}
