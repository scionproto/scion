package base

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/base/ftracker"
	"github.com/netsec-ethz/scion/go/sig/defines"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

var _ = log.Warn

// SDB contains the aggregated information for remote SIGs, ASes and their prefixes
type SDB struct {
	// TODO(scrye) per AS lock granularity
	topo               *topology
	lock               sync.RWMutex
	requestQueue       chan *addr.ISD_AS
	defaultPathTimeout time.Duration
	Global             *defines.Global
}

func NewSDB(global *defines.Global) (*SDB, error) {
	sdb := new(SDB)

	sdb.Global = global
	sdb.topo = newTopology()
	sdb.defaultPathTimeout = 30 * time.Second

	// TODO build request queue
	sdb.requestQueue = make(chan *addr.ISD_AS, 128)

	// Spawn path manager
	go sdb.run()
	return sdb, nil
}

func (sdb *SDB) pathResolver() {
	for {
		ia := <-sdb.requestQueue
		log.Debug("Querying SCIOND for Paths", "ia", ia)
		reply, err := sdb.Global.SCIOND.Paths(ia, sdb.Global.IA, 1,
			sciond.PathReqFlags{Flush: false, Sibra: false})
		if err != nil {
			log.Warn("Path retrieval error", "isdas", ia)
			time.AfterFunc(5*time.Second, func() { sdb.requestQueue <- ia })
			continue
		}

		info, found := sdb.topo.get(ia.String())
		if found == false {
			log.Info("Attempted to query paths for unknown AS", "isdas", ia)
			time.AfterFunc(5*time.Second, func() { sdb.requestQueue <- ia })
			continue
		}
		log.Debug("Got paths", "ia", ia, "paths", reply.Entries)

		if reply.ErrorCode != sciond.ErrorOk {
			log.Info("Path query resolved with error", "isdas", ia, "error", reply.ErrorCode)
			time.AfterFunc(5*time.Second, func() { sdb.requestQueue <- ia })
			continue
		}
		info.updatePaths(reply.Entries)

		// Refire to refresh Paths after 30 seconds
		time.AfterFunc(60*time.Second, func() { sdb.requestQueue <- ia })
	}
}

// run periodically queries SCIOND to keep up to date paths to known SIGs
func (sdb *SDB) run() {
	if sdb.Global.Encapsulation != "scion" {
		// Nothing to do
		return
	}

	// Start one async path worker
	go sdb.pathResolver()
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

func (sdb *SDB) AddSig(isdas string, address string, port string, source string) error {
	sdb.lock.Lock()
	defer sdb.lock.Unlock()

	var err error
	if e, found := sdb.topo.get(isdas); found {
		return e.addSig(address, port, source)
	}

	// Create tunnel interface for remote AS
	info, err := newASInfo(sdb, isdas, ftracker.FMFirst, ftracker.LBFirst)
	if err != nil {
		return err
	}
	sdb.topo.set(isdas, info)

	// Spawn worker for this AS
	// TODO(scrye) channel for data worker commands (to signal remote AS entry destruction/worker)
	go EgressWorker(info)

	// Ask SDB background process to queue SCIOND for paths to this AS
	if sdb.Global.Encapsulation == "scion" {
		ia, err := addr.IAFromString(isdas)
		if err != nil {
			return err
		}
		sdb.requestQueue <- ia
	}
	return info.addSig(address, port, source)
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
