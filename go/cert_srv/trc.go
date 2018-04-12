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

	"github.com/scionproto/scion/go/cert_srv/conf"
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
	ia   addr.IA
}

func NewTRCHandler(conn *snet.Conn, ia addr.IA) *TRCHandler {
	return &TRCHandler{conn: conn, ia: ia}
}

// HandleReq handles TRC requests. If the TRC is not already cached and the cache-only flag is set
// or the requester is from a remote AS, the request is dropped.
func (h *TRCHandler) HandleReq(a *snet.Addr, req *cert_mgmt.TRCReq, config *conf.Conf) {
	log.Info("Received TRC request", "addr", a, "req", req)
	var t *trc.TRC
	if req.Version == cert_mgmt.NewestVersion {
		t = config.Store.GetNewestTRC(req.ISD)
	} else {
		t = config.Store.GetTRC(req.ISD, req.Version)
	}
	srcLocal := config.PublicAddr.IA.Eq(a.IA)
	if t != nil {
		if err := h.sendTRCRep(a, t); err != nil {
			log.Error("Unable to send TRC reply", "addr", a, "req", req, "err", err)
		}
	} else if !srcLocal || req.CacheOnly {
		log.Info("Dropping TRC requeset", "addr", a, "req", req, "err", "TRC not found")
	} else {
		if err := h.fetchTRC(a, req); err != nil {
			log.Error("Unable to fetch TRC", "req", req, "err", err)
		}
	}
}

// sendTRCRep creates a TRC response and sends it to the requester.
func (h *TRCHandler) sendTRCRep(a *snet.Addr, t *trc.TRC) error {
	raw, err := t.Compress()
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.TRC{RawTRC: raw}, nil, nil)
	if err != nil {
		return err
	}
	log.Debug("Send TRC reply", "trc", t, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// fetchTRC fetches a TRC from the remote AS.
func (h *TRCHandler) fetchTRC(a *snet.Addr, req *cert_mgmt.TRCReq) error {
	key := trc.NewKey(req.ISD, req.Version).String()
	sendReq := trcReqCache.Put(key, a)
	if sendReq { // rate limit
		return h.sendTRCReq(req)
	}
	log.Info("Ignoring TRC request (same request already pending)", "addr", a, "req", req)
	return nil
}

// sendTRCReq sends a TRC request to the specified remote AS.
func (h *TRCHandler) sendTRCReq(req *cert_mgmt.TRCReq) error {
	cpld, err := ctrl.NewCertMgmtPld(req, nil, nil)
	if err != nil {
		return err
	}
	pathSet := snet.DefNetwork.PathResolver().Query(h.ia, req.IA())
	path := pathSet.GetAppPath("")
	if path == nil {
		return common.NewBasicError("Unable to find core AS", nil)
	}
	a := &snet.Addr{IA: path.Entry.Path.DstIA(), Host: addr.SvcCS}
	log.Debug("Send TRC request", "req", req, "addr", a)
	return SendPayload(h.conn, cpld, a)
}

// HandleRep handles TRC replies. Pending requests are answered and removed.
func (h *TRCHandler) HandleRep(a *snet.Addr, rep *cert_mgmt.TRC, config *conf.Conf) {
	log.Info("Received TRC reply", "addr", a, "rep", rep)
	t, err := rep.TRC()
	if err != nil {
		log.Error("Unable to parse TRC reply", "err", err)
		return
	}
	if err = config.Store.AddTRC(t, true); err != nil {
		log.Error("Unable to store TRC", "key", t.Key(), "err", err)
		return
	}
	key := t.Key()
	reqVer := chainReqCache.Pop(key.String())
	key.Ver = cert_mgmt.NewestVersion
	reqNew := chainReqCache.Pop(key.String())
	key.Ver = t.Version
	if reqVer == nil && reqNew == nil { // No pending requests
		return
	}
	cpld, err := ctrl.NewCertMgmtPld(rep, nil, nil)
	if err != nil {
		log.Error("Unable to create TRC reply", "key", t.Key(), "err", err)
		return
	}
	h.answerReqs(reqVer, cpld, key)
	h.answerReqs(reqNew, cpld, key)
}

// answerReqs responds to pending requests.
func (h *TRCHandler) answerReqs(reqs *AddrSet, cpld *ctrl.Pld, key *trc.Key) {
	if reqs == nil {
		return
	}
	for _, dst := range reqs.Addrs {
		if err := SendPayload(h.conn, cpld, dst); err != nil {
			log.Error("Unable to write TRC reply", "key", key, "err", err)
			continue
		}
	}
}
