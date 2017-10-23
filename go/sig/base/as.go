// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/vishvananda/netlink"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/sig/egress"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
	"github.com/netsec-ethz/scion/go/sig/siginfo"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

const sigMgrTick = 10 * time.Second

// ASEntry contains all of the information required to interact with a remote AS.
type ASEntry struct {
	sync.RWMutex
	log.Logger
	IA         *addr.ISD_AS
	IAString   string
	Nets       map[string]*NetEntry
	Sigs       siginfo.SigMap
	Session    *egress.Session
	DevName    string
	tunLink    netlink.Link
	tunIO      io.ReadWriteCloser
	sigMgrStop chan struct{}
}

func newASEntry(ia *addr.ISD_AS) (*ASEntry, error) {
	ae := &ASEntry{
		Logger:     log.New("ia", ia),
		IA:         ia,
		IAString:   ia.String(),
		Nets:       make(map[string]*NetEntry),
		Sigs:       make(siginfo.SigMap),
		DevName:    fmt.Sprintf("scion-%s", ia),
		sigMgrStop: make(chan struct{}),
	}
	var err error
	if ae.Session, err = egress.NewSession(ia, 0, ae.SigMap, ae.Logger); err != nil {
		return nil, err
	}
	return ae, nil
}

func (ae *ASEntry) setupNet() error {
	var err error
	ae.tunLink, ae.tunIO, err = xnet.ConnectTun(ae.DevName)
	if err != nil {
		return err
	}
	ae.Info("Network setup done")
	go egress.NewDispatcher(ae.DevName, ae.tunIO, ae.Session).Run()
	go ae.sigMgr()
	ae.Session.Start()
	return nil
}

// AddNet idempotently adds a network for the remote IA.
func (ae *ASEntry) AddNet(ipnet *net.IPNet) error {
	ae.Lock()
	defer ae.Unlock()
	if ae.tunLink == nil {
		// Ensure that the network setup is done, as otherwise route entries can't be added.
		if err := ae.setupNet(); err != nil {
			return err
		}
	}
	key := ipnet.String()
	if _, ok := ae.Nets[key]; ok {
		return nil
	}
	ne, err := newNetEntry(ae.tunLink, ipnet)
	if err != nil {
		return err
	}
	ae.Nets[key] = ne
	ae.Info("Added network", "net", ipnet)
	return nil
}

// DelIA removes a network for the remote IA.
func (ae *ASEntry) DelNet(ipnet *net.IPNet) error {
	ae.Lock()
	key := ipnet.String()
	ne, ok := ae.Nets[key]
	if !ok {
		ae.Unlock()
		return common.NewCError("DelNet: no network found", "ia", ae.IA, "net", ipnet)
	}
	delete(ae.Nets, key)
	ae.Unlock() // Do cleanup outside the lock.
	ae.Info("Removed network", "net", ipnet)
	return ne.Cleanup()
}

// AddSig idempotently adds a SIG for the remote IA.
func (ae *ASEntry) AddSig(id siginfo.SigIdType, ip net.IP,
	ctrlPort, encapPort int, static bool) error {
	ae.Lock()
	defer ae.Unlock()
	if len(id) == 0 {
		return common.NewCError("AddSig: SIG id empty", "ia", ae.IA)
	}
	if ip == nil {
		return common.NewCError("AddSig: SIG address empty", "ia", ae.IA)
	}
	if err := sigcmn.ValidatePort("remote ctrl", ctrlPort); err != nil {
		cerr := err.(*common.CError)
		return cerr.AddCtx(cerr.Ctx, "ia", ae.IA, "id", id)
	}
	if err := sigcmn.ValidatePort("remote encap", encapPort); err != nil {
		cerr := err.(*common.CError)
		return cerr.AddCtx(cerr.Ctx, "ia", ae.IA, "id", id)
	}
	if _, ok := ae.Sigs[id]; ok {
		// FIXME(kormat): support updating SIG entry.
		return nil
	}
	ae.Sigs[id] = siginfo.NewSig(ae.IA, id, addr.HostFromIP(ip), ctrlPort, encapPort, static)
	ae.Info("Added SIG", "sig", ae.Sigs[id])
	return nil
}

// DelSIG removes an SIG for the remote IA.
func (ae *ASEntry) DelSig(id siginfo.SigIdType) error {
	ae.Lock()
	se, ok := ae.Sigs[id]
	if !ok {
		ae.Unlock()
		return common.NewCError("DelSig: no SIG found", "ia", ae.IA, "id", id)
	}
	delete(ae.Sigs, id)
	ae.Unlock() // Do cleanup outside the lock.
	ae.Info("Removed SIG", "id", id)
	return se.Cleanup()
}

// Internal method to return a *copy* of the ASEntry's SigMap
func (ae *ASEntry) SigMap() siginfo.SigMap {
	ae.Lock()
	defer ae.Unlock()
	smap := make(siginfo.SigMap)
	for k, v := range ae.Sigs {
		smap[k] = v
	}
	return smap
}

// manage the Sig map
func (ae *ASEntry) sigMgr() {
	defer liblog.LogPanicAndExit()
	ticker := time.NewTicker(sigMgrTick)
	defer ticker.Stop()
	for {
		// TODO(kormat): handle adding new SIGs from discovery, and updating existing ones.
		select {
		case <-ae.sigMgrStop:
			break
		case <-ticker.C:
			smap := ae.SigMap()
			for _, sig := range smap {
				sig.ExpireFails()
			}
		}
	}
}

func (ae *ASEntry) Cleanup() error {
	ae.Lock()
	defer ae.Unlock()
	// Clean up sigMgr goroutine.
	ae.sigMgrStop <- struct{}{}
	// Clean up the egress dispatcher.
	if err := ae.tunIO.Close(); err != nil {
		ae.Error("Error closing TUN io", "dev", ae.DevName, "err", err)
	}
	// Clean up sessions, and associated workers.
	ae.cleanSessions()
	for _, ne := range ae.Nets {
		if err := ne.Cleanup(); err != nil {
			cerr := err.(*common.CError)
			ae.Error(cerr.Desc, cerr.Ctx...)
		}
	}
	if err := netlink.LinkDel(ae.tunLink); err != nil {
		// Only return this error, as it's the only critical one.
		return common.NewCError("Error removing TUN link",
			"ia", ae.IA, "dev", ae.DevName, "err", err)
	}
	return nil
}

func (ae *ASEntry) cleanSessions() {
	if err := ae.Session.Cleanup(); err != nil {
		ae.Session.Error("Error cleaning up session", "err", err)
	}
}
