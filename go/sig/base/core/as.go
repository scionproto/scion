// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

package core

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/sig/base"
	"github.com/scionproto/scion/go/sig/config"
	"github.com/scionproto/scion/go/sig/egress/dispatcher"
	"github.com/scionproto/scion/go/sig/egress/router"
	"github.com/scionproto/scion/go/sig/egress/session"
	"github.com/scionproto/scion/go/sig/egress/worker"
	"github.com/scionproto/scion/go/sig/internal/sigconfig"
	"github.com/scionproto/scion/go/sig/sigcmn"
	"github.com/scionproto/scion/go/sig/siginfo"
)

const (
	sigMgrTick        = 10 * time.Second
	healthMonitorTick = 5 * time.Second
)

// ASEntry contains all of the information required to interact with a remote AS.
type ASEntry struct {
	sync.RWMutex
	Nets              map[string]*net.IPNet
	Sigs              *siginfo.SigMap
	IA                addr.IA
	IAString          string
	egressRing        *ringbuf.Ring
	sigMgrStop        chan struct{}
	healthMonitorStop chan struct{}
	version           uint64 // used to track certain changes made to ASEntry
	log.Logger

	Session *session.Session
}

func newASEntry(ia addr.IA) (*ASEntry, error) {
	ae := &ASEntry{
		Logger:            log.New("ia", ia),
		IA:                ia,
		IAString:          ia.String(),
		Nets:              make(map[string]*net.IPNet),
		Sigs:              &siginfo.SigMap{},
		sigMgrStop:        make(chan struct{}),
		healthMonitorStop: make(chan struct{}),
	}
	var err error
	pool, err := session.NewPathPool(ia)
	if err != nil {
		return nil, err
	}
	ae.Session, err = session.NewSession(ia, 0, ae.Sigs, ae.Logger, pool, worker.DefaultFactory)
	if err != nil {
		return nil, err
	}
	return ae, nil
}

func (ae *ASEntry) ReloadConfig(cfg *config.ASEntry) bool {
	ae.Lock()
	defer ae.Unlock()
	// Method calls first to prevent skips due to logical short-circuit
	s := ae.addNewSIGS(cfg.Sigs)
	s = ae.delOldSIGS(cfg.Sigs) && s
	s = ae.addNewNets(cfg.Nets) && s
	return ae.delOldNets(cfg.Nets) && s
}

// addNewNets adds the networks in ipnets that are not currently configured.
func (ae *ASEntry) addNewNets(ipnets []*config.IPNet) bool {
	s := true
	for _, ipnet := range ipnets {
		err := ae.addNet(ipnet.IPNet())
		if err != nil {
			ae.Error("Unable to add network", "net", ipnet, "err", err)
			s = false
		}
	}
	return s
}

// delOldNets deletes currently configured networks that are not in ipnets.
func (ae *ASEntry) delOldNets(ipnets []*config.IPNet) bool {
	s := true
Top:
	for k, v := range ae.Nets {
		for _, ipnet := range ipnets {
			if k == ipnet.IPNet().String() {
				continue Top
			}
		}
		err := ae.delNet(v)
		if err != nil {
			ae.Error("Unable to delete network", "net", k, "err", err)
			s = false
		}
	}
	return s
}

// AddNet idempotently adds a network for the remote IA.
func (ae *ASEntry) AddNet(ipnet *net.IPNet) error {
	ae.Lock()
	defer ae.Unlock()
	return ae.addNet(ipnet)
}

func (ae *ASEntry) addNet(ipnet *net.IPNet) error {
	if ae.egressRing == nil {
		// Ensure that the network setup is done
		ae.setupNet()
	}
	key := ipnet.String()
	if _, ok := ae.Nets[key]; ok {
		return nil
	}
	if err := router.NetMap.Add(ipnet, ae.IA, ae.egressRing); err != nil {
		return err
	}
	ae.Nets[key] = ipnet
	ae.version++
	// Generate NetworkChanged event
	params := base.NetworkChangedParams{
		RemoteIA: ae.IA,
		IpNet:    *ipnet,
		Healthy:  ae.checkHealth(),
		Added:    true,
	}
	base.NetworkChanged(params)
	ae.Info("Added network", "net", ipnet)
	return nil
}

// DelNet removes a network for the remote IA.
func (ae *ASEntry) DelNet(ipnet *net.IPNet) error {
	ae.Lock()
	defer ae.Unlock()
	return ae.delNet(ipnet)
}

func (ae *ASEntry) delNet(ipnet *net.IPNet) error {
	key := ipnet.String()
	if _, ok := ae.Nets[key]; !ok {
		return common.NewBasicError("DelNet: no network found", nil, "ia", ae.IA, "net", ipnet)
	}
	if err := router.NetMap.Delete(ipnet); err != nil {
		return err
	}
	delete(ae.Nets, key)
	ae.version++
	// Generate NetworkChanged event
	params := base.NetworkChangedParams{
		RemoteIA: ae.IA,
		IpNet:    *ipnet,
		Healthy:  ae.checkHealth(),
		Added:    false,
	}
	base.NetworkChanged(params)
	ae.Info("Removed network", "net", ipnet)
	return nil
}

// addNewSIGS adds the SIGs in sigs that are not currently configured.
func (ae *ASEntry) addNewSIGS(sigs config.SIGSet) bool {
	s := true
	for _, sig := range sigs {
		ctrlPort := int(sig.CtrlPort)
		if ctrlPort == 0 {
			ctrlPort = sigconfig.DefaultCtrlPort
		}
		encapPort := int(sig.EncapPort)
		if encapPort == 0 {
			encapPort = sigconfig.DefaultEncapPort
		}
		err := ae.AddSig(sig.Id, sig.Addr, ctrlPort, encapPort, true)
		if err != nil {
			ae.Error("Unable to add SIG", "sig", sig, "err", err)
			s = false
		}
	}
	return s
}

// delOldSIGS deletes the currently configured SIGs that are not in sigs.
func (ae *ASEntry) delOldSIGS(sigs config.SIGSet) bool {
	s := true
	ae.Sigs.Range(func(id siginfo.SigIdType, sig *siginfo.Sig) bool {
		if !sig.Static {
			return true
		}
		if _, ok := sigs[sig.Id]; !ok {
			err := ae.DelSig(sig.Id)
			if err != nil {
				ae.Error("Unable to delete SIG", "err", err)
				s = false
			}
		}
		return true
	})
	return s
}

// AddSig idempotently adds a SIG for the remote IA.
func (ae *ASEntry) AddSig(id siginfo.SigIdType, ip net.IP, ctrlPort, encapPort int,
	static bool) error {
	// ae.Sigs is thread safe, no master lock needed
	if len(id) == 0 {
		return common.NewBasicError("AddSig: SIG id empty", nil, "ia", ae.IA)
	}
	if ip == nil {
		return common.NewBasicError("AddSig: SIG address empty", nil, "ia", ae.IA)
	}
	if err := sigcmn.ValidatePort("remote ctrl", ctrlPort); err != nil {
		return common.NewBasicError("Remote ctrl port validation failed", err,
			"ia", ae.IA, "id", id)
	}
	if err := sigcmn.ValidatePort("remote encap", encapPort); err != nil {
		return common.NewBasicError("Remote encap port validation failed", err,
			"ia", ae.IA, "id", id)
	}
	if sig, ok := ae.Sigs.Load(id); ok {
		sig.Host = addr.HostFromIP(ip)
		sig.CtrlL4Port = ctrlPort
		sig.EncapL4Port = encapPort
		ae.Info("Updated SIG", "sig", sig)
	} else {
		sig := siginfo.NewSig(ae.IA, id, addr.HostFromIP(ip), ctrlPort, encapPort, static)
		ae.Sigs.Store(id, sig)
		ae.Info("Added SIG", "sig", sig)
	}
	return nil
}

// DelSIG removes an SIG for the remote IA.
func (ae *ASEntry) DelSig(id siginfo.SigIdType) error {
	// ae.Sigs is thread safe, no master lock needed
	se, ok := ae.Sigs.Load(id)
	if !ok {
		return common.NewBasicError("DelSig: no SIG found", nil, "ia", ae.IA, "id", id)
	}
	ae.Sigs.Delete(id)
	ae.Info("Removed SIG", "id", id)
	return se.Cleanup()
}

// manage the Sig map
func (ae *ASEntry) sigMgr() {
	ticker := time.NewTicker(sigMgrTick)
	defer ticker.Stop()
	ae.Info("sigMgr starting")
Top:
	for {
		// TODO(kormat): handle adding new SIGs from discovery, and updating existing ones.
		select {
		case <-ae.sigMgrStop:
			break Top
		case <-ticker.C:
			ae.Sigs.Range(func(id siginfo.SigIdType, sig *siginfo.Sig) bool {
				sig.ExpireFails()
				return true
			})
		}
	}
	close(ae.sigMgrStop)
	ae.Info("sigMgr stopping")
}

func (ae *ASEntry) monitorHealth() {
	ticker := time.NewTicker(healthMonitorTick)
	defer ticker.Stop()
	ae.Info("Health monitor starting")
	prevHealth := false
	prevVersion := uint64(0)
Top:
	for {
		select {
		case <-ae.healthMonitorStop:
			break Top
		case <-ticker.C:
			ae.performHealthCheck(&prevHealth, &prevVersion)
		}
	}
	close(ae.healthMonitorStop)
	ae.Info("Health monitor stopping")
}

func (ae *ASEntry) performHealthCheck(prevHealth *bool, prevVersion *uint64) {
	ae.RLock()
	defer ae.RUnlock()
	curHealth := ae.checkHealth()
	if curHealth != *prevHealth || ae.version != *prevVersion {
		// Generate slice of networks.
		// XXX: This could become a bottleneck, namely in case of a large number
		// of remote prefixes and flappy health.
		nets := make([]*net.IPNet, 0, len(ae.Nets))
		for _, n := range ae.Nets {
			nets = append(nets, n)
		}
		// Overall health has changed. Generate event.
		params := base.RemoteHealthChangedParams{
			RemoteIA: ae.IA,
			Nets:     nets,
			Healthy:  curHealth,
		}
		base.RemoteHealthChanged(params)
	}
	*prevHealth = curHealth
	*prevVersion = ae.version
}

func (ae *ASEntry) checkHealth() bool {
	return ae.Session.Healthy()
}

func (ae *ASEntry) Cleanup() error {
	ae.Lock()
	defer ae.Unlock()
	// Clean up sigMgr goroutine.
	ae.sigMgrStop <- struct{}{}
	// Clean up health monitor
	ae.healthMonitorStop <- struct{}{}
	// Clean up NetMap entries
	for _, v := range ae.Nets {
		if err := ae.delNet(v); err != nil {
			ae.Error("Error removing networks during cleanup", "err", err)
		}
	}
	ae.egressRing.Close()
	// Clean up sessions, and associated workers.
	ae.cleanSessions()
	return nil
}

func (ae *ASEntry) cleanSessions() {
	if err := ae.Session.Cleanup(); err != nil {
		ae.Session.Error("Error cleaning up session", "err", err)
	}
}

func (ae *ASEntry) setupNet() {
	ae.egressRing = ringbuf.New(64, nil, "egress",
		prometheus.Labels{"ringId": ae.IAString, "sessId": ""})
	go func() {
		defer log.LogPanicAndExit()
		dispatcher.NewDispatcher(ae.IA, ae.egressRing,
			&base.SingleSession{Session: ae.Session}).Run()
	}()
	go func() {
		defer log.LogPanicAndExit()
		ae.sigMgr()
	}()
	go func() {
		defer log.LogPanicAndExit()
		ae.monitorHealth()
	}()
	ae.Session.Start()
	ae.Info("Network setup done")
}
