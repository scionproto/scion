package base

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

var _ = log.Warn

type Topology struct {
	info map[string]*ASInfo
	lock sync.Mutex
}

func NewTopology() *Topology {
	topo := &Topology{}
	topo.info = make(map[string]*ASInfo)
	return topo
}

func (t *Topology) Get(key string) (*ASInfo, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	value, found := t.info[key]
	return value, found
}

func (t *Topology) Set(key string, value *ASInfo) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.info[key] = value
}

func (t *Topology) Print() string {
	output := ""
	for k, v := range t.info {
		output += fmt.Sprintf("  ISDAS %v:\n", k)
		if v.Subnets.Len() == 0 {
			output += fmt.Sprintf("    (no prefixes)\n")
		}
		for e := v.Subnets.Front(); e != nil; e = e.Next() {
			output += fmt.Sprintf("      %v\n", e.Value.(*net.IPNet))
		}
		output += fmt.Sprintf("    reachable via %d SIG(s): ", len(v.sigs))
		for _, endpoint := range v.sigs {
			output += fmt.Sprintf("%v:%v ", endpoint.IP, endpoint.Port)
		}
		output += "\n"
	}
	return output
}

// SDB contains the aggregated information for remote SIGs, ASes and their prefixes
type SDB struct {
	// TODO(scrye) per AS lock granularity
	topo               *Topology
	sciond             *sciond.Connector
	Lock               sync.RWMutex
	RequestQueue       chan string
	DefaultPathTimeout time.Duration
}

func NewSDB(sciondPath string) (*SDB, error) {
	var err error
	sdb := new(SDB)
	sdb.sciond, err = sciond.Connect(sciondPath)
	if err != nil {
		return nil, err
	}
	sdb.topo = NewTopology()
	sdb.DefaultPathTimeout = 30 * time.Second

	// TODO build request queue
	sdb.RequestQueue = make(chan string, 128)

	// Spawn path manager
	go sdb.run()
	return sdb, nil
}

type sciondPackedReply struct {
	err     error
	reply   *sciond.PathReply
	isdas   string
	timeout bool
}

// run periodically queries SCIOND to keep up to date paths to known SIGs
func (sdb *SDB) run() {
	// WiP, not implemented yet
	/*
		replyQueue := make(chan sciondPackedReply, 128)
		for {
			select {
			case isdas := <-sdb.RequestQueue:
				//log.Debug("Requesting paths", "isdas", isdas)
				replyQueue <- sciondPackedReply{err: nil, reply: nil, timeout: false, isdas: isdas}
			case packedReply := <-replyQueue:
				//log.Debug("Received paths")
				// Refire timer before expiration
				time.AfterFunc(5*time.Second, func() { sdb.RequestQueue <- packedReply.isdas })
			}

			// TODO handle SCIOND timeouts
		}
	*/
}

func (sdb *SDB) AddRoute(prefix string, isdas string) error {
	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	info, found := sdb.topo.Get(isdas)
	if !found {
		return common.NewError("Unable to add prefix for unreachable AS", "AS", isdas, "prefix",
			prefix)
	}

	err = info.AddRoute(subnet)
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
	_, subnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return err
	}

	// TODO delete from routing table
	info, found := sdb.topo.Get(isdas)
	if !found {
		return common.NewError("Unable to delete prefix from unreachable AS", "prefix",
			prefix, "AS", isdas)
	}

	return info.DelRoute(subnet)
}

func (sdb *SDB) AddSig(isdas string, address string, port string, source string) error {
	var err error
	if e, found := sdb.topo.Get(isdas); found {
		return e.AddSig(address, port, source)
	}

	// Create tunnel interface for remote AS
	info, err := NewASInfo(isdas)
	info.SDB = sdb
	if err != nil {
		return err
	}
	sdb.topo.Set(isdas, info)

	// Spawn worker for this AS
	// TODO(scrye) channel for data worker commands (to signal remote AS entry destruction/worker)
	go DataPlaneWorker(info)

	// Ask SDB background process to queue SCIOND for paths to this AS
	sdb.RequestQueue <- isdas
	return info.AddSig(address, port, source)
}

func (sdb *SDB) DelSig(isdas string, address string, port string, source string) error {
	if e, found := sdb.topo.Get(isdas); found {
		return e.DelSig(address, port, source)
	}
	return common.NewError("SIG entry not found", "address", address, "port", port)
}

func (sdb *SDB) Print(source string) string {
	return sdb.topo.Print()
}
