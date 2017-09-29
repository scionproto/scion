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

type ASEntry struct {
	sync.RWMutex
	IA           *addr.ISD_AS
	IAString     string
	Nets         map[string]*NetEntry
	Sigs         map[string]*SIGInfo
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
		Sigs:     make(map[string]*SIGInfo),
		DevName:  fmt.Sprintf("scion-%s", ia),
	}
}

func (as *ASEntry) TunIO() (io.ReadWriteCloser, error) {
	as.Lock()
	defer as.Unlock()
	if as.tunLink == nil {
		if err := as.setupNet(); err != nil {
			return nil, err
		}
	}
	return as.tunIO, nil
}

func (as *ASEntry) Conn() (*snet.Conn, error) {
	as.Lock()
	defer as.Unlock()
	if as.tunLink == nil {
		if err := as.setupNet(); err != nil {
			return nil, err
		}
	}
	return as.conn, nil
}

func (as *ASEntry) setupNet() error {
	var err error
	as.tunLink, as.tunIO, err = xnet.ConnectTun(as.DevName)
	if err != nil {
		return err
	}
	// Not using a fixed local port, as this is for outgoing data only.
	as.conn, err = snet.ListenSCION("udp4", &snet.Addr{IA: sigcmn.IA, Host: sigcmn.Host})
	if err != nil {
		return err
	}
	// FIXME(kormat): once policies are implmeneted, workers would be spawned by the policies,
	// and the egress dispatcher would be spawned here (and if we move away from tun-per-IA,
	// then it would be spawned by main())
	go NewEgressWorker(as, as.tunIO).Run()
	log.Debug("Network setup done", "ia", as.IA)
	return nil
}

func (as *ASEntry) AddNet(ipnet *net.IPNet) error {
	as.Lock()
	defer as.Unlock()
	if as.tunLink == nil {
		// Ensure that the network setup is done, as otherwise route entries can't be added.
		if err := as.setupNet(); err != nil {
			return err
		}
	}
	key := ipnet.String()
	if _, ok := as.Nets[key]; ok {
		return nil
	}
	ne, err := newNetEntry(as.tunLink, ipnet)
	if err != nil {
		return err
	}
	as.Nets[key] = ne
	log.Debug("Added network", "ia", as.IA, "net", ipnet)
	return nil
}

func (as *ASEntry) DelNet(ipnet *net.IPNet) error {
	as.Lock()
	key := ipnet.String()
	ne, ok := as.Nets[key]
	if !ok {
		as.Unlock()
		return common.NewCError("DelNet: Network not found", "ia", as.IA, "net", ipnet)
	}
	delete(as.Nets, key)
	as.Unlock()
	log.Debug("Removed network", "ia", as.IA, "net", ipnet)
	return ne.Cleanup()
}

func (as *ASEntry) AddSig(id string, ip net.IP, ctrlPort, encapPort int, static bool) bool {
	as.Lock()
	defer as.Unlock()
	if _, ok := as.Sigs[id]; ok {
		return false
	}
	as.Sigs[id] = NewSIGInfo(as.IA, id, addr.HostFromIP(ip), ctrlPort, encapPort, static)
	log.Debug("Added SIG", "ia", as.IA, "sig", as.Sigs[id])
	return true
}

func (as *ASEntry) DelSig(id string) bool {
	as.Lock()
	defer as.Unlock()
	entry, ok := as.Sigs[id]
	if !ok {
		return false
	}
	delete(as.Sigs, id)
	log.Debug("Removed SIG", "ia", as.IA, "sig", entry)
	// TODO(kormat): notify keepalive thread to reevaluate SIGs.
	return true
}

func (as *ASEntry) CurrSig() *SIGInfo {
	// FIXME(kormat): this is temporary, until we have policies managing this.
	for _, sig := range as.Sigs {
		return sig
	}
	return nil
}

func (as *ASEntry) Cleanup() error {
	as.Lock()
	defer as.Unlock()
	// FIXME(kormat): cleanup path policies and their goroutines.
	for _, ne := range as.Nets {
		if err := ne.Cleanup(); err != nil {
			cerr := err.(*common.CError)
			log.Error(cerr.Desc, cerr.Ctx...)
		}
	}
	if err := as.tunIO.Close(); err != nil {
		log.Error("Error closing TUN io", "ia", as.IA, "dev", as.DevName, "err", err)
	}
	if err := netlink.LinkDel(as.tunLink); err != nil {
		// Only return this error, as it's the only critical one.
		return common.NewCError("Error removing TUN link",
			"ia", as.IA, "dev", as.DevName, "err", err)
	}
	return as.conn.Close()
}

func (as *ASEntry) String() string {
	as.RLock()
	defer as.RUnlock()

	output := fmt.Sprintf("ISDAS %v:\n", as.IA)
	output += "  SIGs:\n"
	if len(as.Sigs) == 0 {
		output += fmt.Sprintf("    (no SIGs)\n")
	}
	for sig := range as.Sigs {
		output += "    " + sig + "\n"
	}
	output += "Prefixes:\n"
	if len(as.Nets) == 0 {
		output += fmt.Sprintf("    (no prefixes)\n")
	}
	for key := range as.Nets {
		output += "    " + key + "\n"
	}
	return output
}
