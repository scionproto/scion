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
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/egress/dispatcher"
	"github.com/scionproto/scion/go/sig/egress/router"
	"github.com/scionproto/scion/go/sig/egress/session"
	"github.com/scionproto/scion/go/sig/egress/worker"
)

const (
	healthMonitorTick = 5 * time.Second
)

// ASEntry contains all of the information required to interact with a remote AS.
type ASEntry struct {
	sync.RWMutex
	Nets              map[string]*net.IPNet
	IA                addr.IA
	IAString          string
	egressRing        *ringbuf.Ring
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
		healthMonitorStop: make(chan struct{}),
	}
	var err error
	pool, err := session.NewPathPool(ia)
	if err != nil {
		return nil, err
	}
	ae.Session, err = session.NewSession(ia, 0, ae.Logger, pool, worker.DefaultFactory)
	if err != nil {
		return nil, err
	}
	return ae, nil
}

func (ae *ASEntry) ReloadConfig(cfg *config.ASEntry) bool {
	ae.Lock()
	defer ae.Unlock()
	// Method calls first to prevent skips due to logical short-circuit
	s := ae.addNewNets(cfg.Nets)
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
	ae.egressRing = ringbuf.New(egress.EgressRemotePkts, nil, "egress",
		prometheus.Labels{"ringId": ae.IAString, "sessId": ""})
	go func() {
		defer log.LogPanicAndExit()
		dispatcher.NewDispatcher(ae.IA, ae.egressRing,
			&base.SingleSession{Session: ae.Session}).Run()
	}()
	go func() {
		defer log.LogPanicAndExit()
		ae.monitorHealth()
	}()
	ae.Session.Start()
	ae.Info("Network setup done")
}
