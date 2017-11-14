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
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/cs/msg"
	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/crypto/cert"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/ctrl/cert_mgmt"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

var (
	// chainReqCache is an expiring cache for pending requests of certificate chains.
	chainReqCache = NewReqCache(30*time.Second, 10*time.Minute, 100*time.Millisecond)
)

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
		log.Info("Dropping certificate chain request", "addr", addr, "req", req, "err",
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
	return SendPayload(conn, cpld, addr, pool)
}

// fetchChain fetches certificate chain from the remote AS.
func fetchChain(addr *snet.Addr, req *cert_mgmt.ChainReq, conn *snet.Conn, pool *msg.BufPool) error {
	key := cert.NewKey(req.IA(), int(req.Version)).String()
	sendReq := chainReqCache.Put(key, addr)
	if sendReq { // rate limit
		log.Info("Dropping certificate chain fetch. Pending request and delta has not "+
			"passed", "addr", addr, "req", req)
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
	log.Debug("Send Chain request", "req", req, "addr", a)
	return SendPayload(conn, cpld, a, pool)
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
	reqs := chainReqCache.Pop(chain.Key().String())
	if reqs == nil { // No pending requests
		return
	}
	cpld, err := ctrl.NewCertMgmtPld(rep)
	if err != nil {
		log.Error("Unable to create certificate chain reply", "err", err)
		return
	}
	for _, dst := range reqs.Addrs {
		if err := SendPayload(conn, cpld, dst, pool); err != nil {
			log.Error("Unable to write certificate chain reply", "err", err)
			continue
		}
	}
}
