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

package main

import (
	"sync"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/patrickmn/go-cache"

	"github.com/netsec-ethz/scion/go/cs/msg"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto/cert"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/ctrl/cert_mgmt"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

const (
	// chainReqDelta is the minimal time between two requests for the same certificate chain.
	chainReqDelta = 1 * time.Second
)

var (
	// chainReqCache is an expiring cache for pending requests of certificate chains.
	chainReqCache = cache.New(30*time.Second, 10*time.Minute)
	// chainCacheLock is the lock for synchronizing access ot chainReqCache.
	chainCacheLock sync.RWMutex
)

// CertReqSet is a struct holding the requester of an pending certificate chain request and
// the timestamp, when the last request was sent for rate limiting.
type CertReqSet struct {
	// Addrs is a set of requester for an pending certificate chain request.
	Addrs map[string]*snet.Addr
	// LastReq is a timestamp when the last certificate chain request has been issued.
	LastReq time.Time
}

// Put adds requester address to the set ouf pending requester.
func (c *CertReqSet) Put(addr *snet.Addr) {
	c.Addrs[addr.String()] = addr.Copy()
}

// SendNewReq returns a boolean, indicating, whether a new certificate chain request shall be
// issued. If the return value is true, the timestamp of the last request is updated.
func (c *CertReqSet) SendNewReq() bool {
	if c.LastReq.Add(chainReqDelta).Before(time.Now()) {
		c.LastReq = time.Now()
		return true
	}
	return false
}

// HandleChainReq handles certificate chain requests. Non-local or cache-only requests are dropped,
// if the certificate chain is not present.
func HandleChainReq(addr *snet.Addr, req *cert_mgmt.ChainReq, conn *snet.Conn, pool *msg.BufPool) {
	log.Info("Received certificate chain request", "addr", addr, "req", req)
	chain := store.GetChain(req.IA(), int(req.Version))
	local := local.IA.Eq(addr.IA)
	if chain != nil {
		if err := sendChainRep(addr, chain, conn, pool); err != nil {
			log.Error("Unable to send certificate chain reply", "addr", addr, "err", err)
		}
	} else if !local || req.CacheOnly {
		log.Info("Dropping certificate chain requeset", "addr", addr, "req", req, "err",
			"certificate chain not found")
	} else {
		if err := fetchChain(addr, req, conn, pool); err != nil {
			log.Error("Unable to fetch certificate chain", "err", err)
		}
	}
}

// sendChainRep creates a certificate chain response and sends it to the requester.
func sendChainRep(addr *snet.Addr, chain *cert.Chain, conn *snet.Conn, pool *msg.BufPool) error {
	raw, err := chain.Compress()
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.ChainRep{RawChain: raw})
	if err != nil {
		return err
	}
	log.Debug("Send Chain reply", "chain", chain, "addr", addr)
	return SendPayload(addr, cpld, conn, pool)
}

// fetchChain fetches certificate chain from the remote AS.
func fetchChain(addr *snet.Addr, req *cert_mgmt.ChainReq, conn *snet.Conn, pool *msg.BufPool) error {
	key := (&cert.Key{IA: *req.IA(), Ver: int(req.Version)}).String()
	chainCacheLock.Lock()
	val, ok := chainReqCache.Get(key)
	if !ok {
		val = &CertReqSet{Addrs: make(map[string]*snet.Addr)}
		chainReqCache.SetDefault(key, val)
	}
	val.(*CertReqSet).Put(addr)
	sendReq := val.(*CertReqSet).SendNewReq()
	chainCacheLock.Unlock()
	if sendReq { // rate limit
		return sendChainReq(req, conn, pool)
	}
	return nil
}

// sendChainReq sends a certificate chain request to the specified remote AS.
func sendChainReq(req *cert_mgmt.ChainReq, conn *snet.Conn, pool *msg.BufPool) error {
	req.CacheOnly = true
	cpld, err := ctrl.NewCertMgmtPld(req)
	if err != nil {
		return err
	}
	a := &snet.Addr{IA: req.IA(), Host: addr.SvcCS, L4Port: 0}
	log.Debug("Send Chain reply", "req", req, "addr", a)
	return SendPayload(a, cpld, conn, pool)
}

// HandleChainRep handles certificate chain replies. Pending requests are answered and removed.
func HandleChainRep(addr *snet.Addr, rep *cert_mgmt.ChainRep, conn *snet.Conn, pool *msg.BufPool) {
	log.Info("Received certificate chain reply", "addr", addr, "rep", rep)
	chain, err := rep.Chain()
	if err != nil {
		log.Error("Unable to parse certificate reply", "err", err)
	}
	if err = store.AddChain(chain, true); err != nil {
		log.Error("Unable to store certificate chain", "err", err)
		return
	}
	key := chain.Key().String()
	chainCacheLock.Lock()
	val, ok := chainReqCache.Get(key)
	if !ok { // No pending requests
		chainCacheLock.Unlock()
		return
	}
	chainReqCache.Delete(key)
	chainCacheLock.Unlock()
	cpld, err := ctrl.NewCertMgmtPld(rep)
	if err != nil {
		log.Error("Unable to create certificate chain reply", "err", err)
		return
	}
	for _, dst := range val.(*CertReqSet).Addrs {
		if err := SendPayload(dst, cpld, conn, pool); err != nil {
			log.Error("Unable to write certificate chain reply", "err", err)
			continue
		}
	}
}
