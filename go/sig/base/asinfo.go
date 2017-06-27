package base

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/base/ftracker"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

type asInfo struct {
	Name string
	IA   *addr.ISD_AS
	SDB  *SDB

	flows *ftracker.FlowTracker

	// NOTE(scrye): A map would probably be a better fit for subnets
	Subnets *list.List

	Device     io.ReadWriteCloser
	DeviceName string

	lock sync.Mutex
}

// newASInfo initializes the internal structures and creates the tunnel interface for a new remote AS.
func newASInfo(sdb *SDB, isdas string, fm ftracker.FlowManager, lb ftracker.LoadBalancer) (*asInfo, error) {
	var err error
	info := new(asInfo)
	info.DeviceName = fmt.Sprintf("scion.%s", isdas)

	ia, nerr := addr.IAFromString(isdas)
	if nerr != nil {
		return nil, nerr
	}
	info.IA = ia
	info.SDB = sdb
	info.flows = ftracker.NewFlowMap(sdb.Global, info.IA, fm, lb)

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

func (as *asInfo) addSig(address string, port string, source string) error {
	as.lock.Lock()
	defer as.lock.Unlock()

	err := as.flows.AddSig(address, port)
	if err != nil {
		return err
	}
	return nil
}

func (as *asInfo) delSig(address string, port string, source string) error {
	as.lock.Lock()
	defer as.lock.Unlock()
	return as.flows.DelSig(address, port)
}

func (as *asInfo) updatePaths(paths []sciond.PathReplyEntry) {
	as.lock.Lock()
	defer as.lock.Unlock()
	as.flows.UpdatePaths(ftracker.PathSetFromSlice(paths))
}

func (as *asInfo) getConn() (*ftracker.Flow, error) {
	// Synchronization happens in the flow tracker
	return as.flows.GetFlow()
}
