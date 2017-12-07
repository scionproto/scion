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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/trc"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	// trcReqCache is an expiring cache for pending requests of TRCs.
	trcReqCache = NewReqCache(30*time.Second, 10*time.Minute, 1*time.Second)
)

type TRCHandler struct {
	conn *snet.Conn
}

func NewTRCHandler(conn *snet.Conn) *TRCHandler {
	return &TRCHandler{conn: conn}
}

// HandleReq handles TRC requests. If the TRC is not already cached and the cache-only flag is set
// or the requester is from a remote AS, the request is dropped.
func (h *TRCHandler) HandleReq(addr *snet.Addr, req *cert_mgmt.TRCReq) {
	log.Info("Received TRC request", "addr", addr, "req", req)
	t := store.GetTRC(uint16(req.ISD()), req.Version)
	srcLocal := public.IA.Eq(addr.IA)
	if t != nil {
		if err := h.sendTRCRep(addr, t); err != nil {
			log.Error("Unable to send TRC reply", "addr", addr, "req", req, "err", err)
		}
	} else if !srcLocal || req.CacheOnly {
		log.Info("Dropping TRC requeset", "addr", addr, "req", req, "err", "TRC not found")
	} else {
		if err := h.fetchTRC(addr, req); err != nil {
			log.Error("Unable to fetch TRC", "req", req, "err", err)
		}
	}
}

// sendTRCRep creates a TRC response and sends it to the requester.
func (h *TRCHandler) sendTRCRep(addr *snet.Addr, t *trc.TRC) error {
	raw, err := t.Compress()
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.TRCRep{RawTRC: raw})
	if err != nil {
		return err
	}
	log.Debug("Send TRC reply", "trc", t, "addr", addr)
	return SendPayload(h.conn, cpld, addr)
}

// fetchTRC fetches a TRC from the remote AS.
func (h *TRCHandler) fetchTRC(addr *snet.Addr, req *cert_mgmt.TRCReq) error {
	key := trc.NewKey(uint16(req.ISD()), req.Version).String()
	sendReq := trcReqCache.Put(key, addr)
	if sendReq { // rate limit
		return h.sendTRCReq(req)
	}
	log.Info("Ignoring TRC request (same request already pending)", "addr", addr, "req", req)
	return nil
}

// sendTRCReq sends a TRC request to the specified remote AS.
func (h *TRCHandler) sendTRCReq(req *cert_mgmt.TRCReq) error {
	cpld, err := ctrl.NewCertMgmtPld(req)
	if err != nil {
		return err
	}
	pathSet := snet.DefNetwork.PathResolver().Query(
		public.IA, &addr.ISD_AS{I: req.RawIA.IA().I, A: 0})
	path := pathSet.GetAppPath("")
	if path == nil {
		return common.NewCError("Unable to find core AS")
	}
	a := &snet.Addr{IA: path.Entry.Path.DstIA(), Host: addr.SvcCS}
	log.Debug("Send TRC request", "req", req, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// HandleRep handles TRC replies. Pending requests are answered and removed.
func (h *TRCHandler) HandleRep(addr *snet.Addr, rep *cert_mgmt.TRCRep) {
	log.Info("Received TRC reply", "addr", addr, "rep", rep)
	t, err := rep.TRC()
	if err != nil {
		log.Error("Unable to parse TRC reply", "err", err)
		return
	}
	if err = store.AddTRC(t, true); err != nil {
		log.Error("Unable to store TRC", "key", t.Key(), "err", err)
		return
	}
	reqs := trcReqCache.Pop(t.Key().String())
	if reqs == nil {
		return
	}
	cpld, err := ctrl.NewCertMgmtPld(rep)
	if err != nil {
		log.Error("Unable to create TRC reply", "key", t.Key(), "err", err)
		return
	}
	for _, dst := range reqs.Addrs {
		if err := SendPayload(h.conn, cpld, dst); err != nil {
			log.Error("Unable to write TRC reply", "key", t.Key(), "err", err)
			continue
		}
	}
}
