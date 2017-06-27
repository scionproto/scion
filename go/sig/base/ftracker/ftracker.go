// Package ftracker manages the flows for a single remote AS
//
// A flow is described by the remote SIG (its L3 address and L4 port) and a valid SCION Path
package ftracker

import (
	"net"
	"strconv"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/sig/conn/scion"
	"github.com/netsec-ethz/scion/go/sig/defines"
)

type FlowManager int

const (
	FMFirst FlowManager = iota
	FMFullMesh
)

func (fm FlowManager) String() string {
	switch fm {
	case FMFirst:
		return "First"
	case FMFullMesh:
		return "FullMesh"
	default:
		return "Unknown"
	}
}

type LoadBalancer int

const (
	LBFirst LoadBalancer = iota
	LBRoundRobin
)

func (lb LoadBalancer) String() string {
	switch lb {
	case LBFirst:
		return "First"
	case LBRoundRobin:
		return "RoundRobin"
	default:
		return "Unknown"
	}
}

type Flow struct {
	Conn net.Conn
	MTU  int
}

type address struct {
	IP   string
	Port string
}

type FlowTracker struct {
	lock   sync.Mutex
	sigs   map[string]address
	paths  PathSet
	flows  map[string]Flow
	lb     LoadBalancer
	fm     FlowManager
	global *defines.Global
	ia     *addr.ISD_AS

	fmFirst struct {
		sig      string
		path     string
		sigInfo  address
		pathInfo sciond.PathReplyEntry
		active   bool
	}
}

func NewFlowMap(global *defines.Global, as *addr.ISD_AS, fm FlowManager, lb LoadBalancer) *FlowTracker {
	f := &FlowTracker{}
	f.global = global
	f.paths = make(PathSet)
	f.sigs = make(map[string]address)
	f.flows = make(map[string]Flow)
	f.ia = as

	// NOTE(scrye): Only support FMFirst and LBFirst for now
	if fm != FMFirst {
		log.Crit("Unsupported flow manager", "fm", fm)
		panic("Unsupported flow manager")
	}
	f.fm = fm

	if lb != LBFirst {
		log.Crit("Unsupported load balancer", "lb", lb)
		panic("Unsupported load balancer")
	}
	f.lb = lb

	return f
}

func (f *FlowTracker) AddSig(ip string, port string) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	sig := ip + ":" + port
	if _, found := f.sigs[sig]; found {
		return common.NewError("SIG entry exists", "sig", sig)
	}
	f.sigs[sig] = address{IP: ip, Port: port}

	switch f.fm {
	case FMFirst:
		err := f.selectFlow()
		if err != nil {
			log.Debug("Unable to select valid flow", "cause", err)
		}
	case FMFullMesh:
		return common.NewError("Flow manager not implemented", "fm", f.fm)
	}

	return nil
}

func (f *FlowTracker) DelSig(ip string, port string) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	return common.NewError("Not implemented", "function", "DelSig")
}

func (f *FlowTracker) UpdatePaths(paths PathSet) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if len(paths) == 0 {
		return nil
	}

	switch f.fm {
	case FMFirst:
		f.paths.removeExcept(paths)
		f.paths.insert(paths)
		err := f.selectFlow()
		if err != nil {
			log.Debug("Unable to select valid flow", "cause", err)
		}
	case FMFullMesh:
		return common.NewError("Flow manager not implemented", "fm", f.fm)
	}

	return nil
}

func (f *FlowTracker) selectFlow() error {
	if f.fmFirst.active == true {
		return nil
	}

	var foundPath bool
	for k, v := range f.paths {
		f.fmFirst.path = k
		f.fmFirst.pathInfo = v
		foundPath = true
	}
	if foundPath == false {
		return common.NewError("Path not found", "sigs", f.sigs, "paths", f.paths)
	}

	var foundSig bool
	for k, v := range f.sigs {
		f.fmFirst.sig = k
		f.fmFirst.sigInfo = v
		foundSig = true
	}
	if foundSig == false {
		return common.NewError("SIG not found", "sigs", f.sigs, "paths", f.paths)
	}

	sigInfo := f.fmFirst.sigInfo
	pathInfo := f.fmFirst.pathInfo

	ip := net.ParseIP(sigInfo.IP)
	if ip == nil {
		return common.NewError("Unable to parse IP address", "address", sigInfo.IP)
	}

	nport, err := strconv.ParseUint(sigInfo.Port, 10, 16)
	if err != nil {
		return common.NewError("Unable to parse port", "port", nport, "err", err)
	}

	var conn net.Conn
	switch f.global.Encapsulation {
	case "ip":
		remote := &net.UDPAddr{IP: ip, Port: int(nport)}
		conn, err = net.DialUDP("udp", nil, remote)
		if err != nil {
			return common.NewError("Unable to establish flow", "err", err)
		}
	case "scion":
		conn, err = scion.New(nil,
			f.global.IA, f.global.Addr, f.global.Port,
			f.ia, addr.HostFromIP(ip), uint16(nport), pathInfo)
		if err != nil {
			return common.NewError("Unable to establish flow", "err", err)
		}
	default:
		return common.NewError("Unknown encapsulation", "encapsulation", f.global.Encapsulation)
	}

	// Everything worked ok, promote to active flow
	f.fmFirst.active = true

	// Register in active flow table
	flowID := getFlowID(f.fmFirst.sig, f.fmFirst.path)
	f.flows[flowID] = Flow{Conn: conn, MTU: int(pathInfo.Path.Mtu)}
	log.Debug("Added flow", "flowID", flowID, "data", f.flows[flowID])

	log.Debug("Selected active flow", "flowID", flowID)
	return nil
}

func (f *FlowTracker) GetFlow() (*Flow, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	flowID := getFlowID(f.fmFirst.sig, f.fmFirst.path)
	flow, ok := f.flows[flowID]
	if ok == false {
		return nil, common.NewError("Unable to retrieve flow", "flowID", flowID)
	}
	return &flow, nil
}

func getFlowID(sig string, path string) string {
	return sig + "." + path
}

type PathSet map[string]sciond.PathReplyEntry

func PathSetFromSlice(paths []sciond.PathReplyEntry) PathSet {
	s := make(PathSet)
	for _, v := range paths {
		s[string(v.Path.FwdPath)] = v
	}
	return s
}

func (s PathSet) removeExcept(op PathSet) {
	for k := range s {
		if _, found := op[k]; !found {
			delete(s, k)
		}
	}
}

func (s PathSet) insert(op PathSet) {
	for k, v := range op {
		s[k] = v
	}
}

func (s PathSet) remove(op PathSet) {
	for k := range op {
		delete(s, k)
	}
}
