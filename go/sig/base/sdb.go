package base

import (
	"fmt"
	"net"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

// SDB contains the aggregated information for remote SIGs, ASes and their prefixes
type SDB struct {
	// TODO(scrye) per AS lock granularity
	topo *topology
	lock sync.RWMutex
	//helloModule *hello.Module
}

func NewSDB() (*SDB, error) {
	sdb := new(SDB)
	sdb.topo = newTopology()
	// FIXME(scrye): reactivate keepalive module
	//sdb.helloModule = hello.NewModule()
	return sdb, nil
}

func (sdb *SDB) AddRoute(prefix string, isdas string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	info, found := sdb.topo.get(isdas)
	if !found {
		return common.NewError("Unable to add prefix for unreachable AS", "AS", isdas, "prefix",
			prefix)
	}

	err = info.addRoute(subnet)
	if err != nil {
		return err
	}

	// TODO define consistency model between this information and the Linux routing table
	err = xnet.AddRouteIF(subnet, info.DeviceName)
	if err != nil {
		log.Error("Unable to add route", "subnet", subnet, "device", info.DeviceName)
		return err
	}

	return nil
}

func (sdb *SDB) DelRoute(prefix string, isdas string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	// TODO delete from routing table
	info, found := sdb.topo.get(isdas)
	if !found {
		return common.NewError("Unable to delete prefix from unreachable AS", "prefix",
			prefix, "AS", isdas)
	}

	return info.delRoute(subnet)
}

func (sdb *SDB) AddSig(isdas string, encapAddr string, encapPort string, ctrlAddr string, ctrlPort string, source string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	var err error
	if e, found := sdb.topo.get(isdas); found {
		return e.addSig(encapAddr, encapPort, ctrlAddr, ctrlPort, source)
	}

	// Create tunnel interface for remote AS
	info, err := newASInfo(sdb, isdas)
	if err != nil {
		return err
	}
	sdb.topo.set(isdas, info)

	// Spawn worker for this AS
	// TODO(scrye) channel for data worker commands (to signal remote AS entry destruction/worker)
	go EgressWorker(info)
	return info.addSig(encapAddr, encapPort, ctrlAddr, ctrlPort, source)
}

func (sdb *SDB) DelSig(isdas string, address string, port string, source string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	if e, found := sdb.topo.get(isdas); found {
		return e.delSig(address, port, source)
	}
	return common.NewError("SIG entry not found", "address", address, "port", port)
}

func (sdb *SDB) Print(source string) string {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	return sdb.topo.print()
}

// topology keeps track of which ASes have been defined
type topology struct {
	info map[string]*asInfo
	lock sync.Mutex
}

func newTopology() *topology {
	topo := &topology{}
	topo.info = make(map[string]*asInfo)
	return topo
}

func (t *topology) get(key string) (*asInfo, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	value, found := t.info[key]
	return value, found
}

func (t *topology) set(key string, value *asInfo) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.info[key] = value
}

func (t *topology) print() string {
	output := ""
	for k, v := range t.info {
		output += fmt.Sprintf("  ISDAS %v:\n", k)
		if v.Subnets.Len() == 0 {
			output += fmt.Sprintf("    (no prefixes)\n")
		}
		for e := v.Subnets.Front(); e != nil; e = e.Next() {
			output += fmt.Sprintf("      %v\n", e.Value.(*net.IPNet))
		}
		output += "\n"
	}
	return output
}
