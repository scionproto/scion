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

	log "github.com/inconshreveable/log15"
	"github.com/vishvananda/netlink"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
	"github.com/netsec-ethz/scion/go/sig/xnet"
)

// ASEntry contains all of the information required to interact with a remote AS.
type ASEntry struct {
	sync.RWMutex
	IA           *addr.ISD_AS
	IAString     string
	Nets         map[string]*NetEntry
	Sigs         map[string]*SIGEntry
	PathPolicies []PathPolicy
	DevName      string
	tunLink      netlink.Link
	tunIO        io.ReadWriteCloser
	// FIXME(kormat): Having the conn object here is temporary, it will live
	// inside the policy objects when they are implemented.
	conn *snet.Conn
}

func newASEntry(ia *addr.ISD_AS) *ASEntry {
	return &ASEntry{
		IA:       ia,
		IAString: ia.String(),
		Nets:     make(map[string]*NetEntry),
		Sigs:     make(map[string]*SIGEntry),
		DevName:  fmt.Sprintf("scion-%s", ia),
	}
}

// TunIO returns the io.ReadWriteCloser for the TUN interface for the remote AS,
// doing the required setup first if necessary.
func (ae *ASEntry) TunIO() (io.ReadWriteCloser, error) {
	ae.Lock()
	defer ae.Unlock()
	if ae.tunLink == nil {
		if err := ae.setupNet(); err != nil {
			return nil, err
		}
	}
	return ae.tunIO, nil
}

// Conn returns the snet.Conn for sending traffic to the remote AS,
// doing the required setup first if necessary.
func (ae *ASEntry) Conn() (*snet.Conn, error) {
	ae.Lock()
	defer ae.Unlock()
	if ae.tunLink == nil {
		if err := ae.setupNet(); err != nil {
			return nil, err
		}
	}
	return ae.conn, nil
}

func (ae *ASEntry) setupNet() error {
	var err error
	ae.tunLink, ae.tunIO, err = xnet.ConnectTun(ae.DevName)
	if err != nil {
		return err
	}
	// Not using a fixed local port, as this is for outgoing data only.
	ae.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	if err != nil {
		return err
	}
	// FIXME(kormat): once policies are implmeneted, workers would be spawned by the policies,
	// and the egress dispatcher would be spawned here (and if we move away from tun-per-IA,
	// then it would be spawned by main())
	go NewEgressWorker(ae, ae.tunIO).Run()
	log.Info("Network setup done", "ia", ae.IA)
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
	log.Info("Added network", "ia", ae.IA, "net", ipnet)
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
	log.Info("Removed network", "ia", ae.IA, "net", ipnet)
	return ne.Cleanup()
}

// AddNet idempotently adds a SIG for the remote IA.
func (ae *ASEntry) AddSig(id string, ip net.IP, ctrlPort, encapPort int, static bool) error {
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
	ae.Sigs[id] = NewSIGInfo(ae.IA, id, addr.HostFromIP(ip), ctrlPort, encapPort, static)
	log.Info("Added SIG", "ia", ae.IA, "sig", ae.Sigs[id])
	return nil
}

// DelSIG removes an SIG for the remote IA.
func (ae *ASEntry) DelSig(id string) error {
	ae.Lock()
	se, ok := ae.Sigs[id]
	if !ok {
		ae.Unlock()
		return common.NewCError("DelSig: no SIG found", "ia", ae.IA, "id", id)
	}
	delete(ae.Sigs, id)
	ae.Unlock() // Do cleanup outside the lock.
	log.Info("Removed SIG", "ia", ae.IA, "id", id)
	// TODO(kormat): notify keepalive thread to reevaluate SIGs.
	return se.Cleanup()
}

// FIXME(kormat): this is temporary, until we have policies managing this.
func (ae *ASEntry) CurrSig() *SIGEntry {
	for _, sig := range ae.Sigs {
		return sig
	}
	return nil
}

func (ae *ASEntry) Cleanup() error {
	ae.Lock()
	defer ae.Unlock()
	// FIXME(kormat): cleanup path policies and their goroutines.
	for _, ne := range ae.Nets {
		if err := ne.Cleanup(); err != nil {
			cerr := err.(*common.CError)
			log.Error(cerr.Desc, cerr.Ctx...)
		}
	}
	if err := ae.tunIO.Close(); err != nil {
		log.Error("Error closing TUN io", "ia", ae.IA, "dev", ae.DevName, "err", err)
	}
	if err := netlink.LinkDel(ae.tunLink); err != nil {
		// Only return this error, as it's the only critical one.
		return common.NewCError("Error removing TUN link",
			"ia", ae.IA, "dev", ae.DevName, "err", err)
	}
	return ae.conn.Close()
}
