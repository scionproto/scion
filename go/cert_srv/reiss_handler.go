// Copyright 2018 ETH Zurich
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
	"bytes"
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	HandlerTimeout = 5 * time.Second
)

// ReissHandler handles certificate chain reissue requests and replies.
//
// Reissue requests are sent by non-issuer ASes to issuer ASes. The request
// needs to be signed with the private key associated with the newest verifying
// key in the customer mapping. Certificate chains are issued automatically by
// the issuer ASes.
type ReissHandler struct{}

func (h *ReissHandler) Handle(r *infra.Request) {
	// Bind the handler to a snapshot of the current config
	h.HandleReq(r, conf.Get())
}

// HandleReq handles certificate chain reissue requests. If the requested
// certificate chain is already present, the existing certificate chain is
// resent. Otherwise, a new certificate chain is issued.
func (h *ReissHandler) HandleReq(r *infra.Request, config *conf.Conf) {
	ctx, cancelF := context.WithTimeout(r.Context(), HandlerTimeout)
	defer cancelF()

	saddr := r.Peer.(*snet.Addr)
	req := r.Message.(*cert_mgmt.ChainIssReq)
	signed := r.FullMessage.(*ctrl.SignedPld)

	log.Debug("[ReissHandler] Received certificate reissue request", "addr", saddr, "req", req)
	if !config.Topo.Core {
		log.Warn("[ReissHandler] Received certificate reissue request as non-issuer AS",
			"addr", saddr, "req", req)
		return
	}
	// Validate the request was correctly signed by the requester
	verChain, err := h.validateSign(ctx, saddr, signed, config)
	if err != nil {
		h.logDropReq(saddr, req, err)
		return
	}
	// Parse the requested certificate
	crt, err := req.Cert()
	if err != nil {
		h.logDropReq(saddr, req, err)
		return
	}
	// Respond with max chain for outdated requests.
	maxChain, err := config.Store.GetChain(ctx, verChain.Leaf.Subject, scrypto.LatestVer)
	if err != nil {
		h.logDropReq(saddr, req, err)
		return
	}
	if maxChain != nil && crt.Version <= maxChain.Leaf.Version {
		log.Debug("[ReissHandler] Resending certificate chain", "addr", saddr, "req", req)
		if err := h.sendRep(ctx, saddr, maxChain, r.ID); err != nil {
			log.Error("[ReissHandler] Unable to resend certificate chain", "addr", saddr,
				"req", req, "err", err)
		}
		return
	}
	// Get the verifying key from the customer mapping
	verKey, err := config.Customers.GetVerifyingKey(saddr.IA)
	if err != nil {
		h.logDropReq(saddr, req, err)
		return
	}
	// Verify request and check the verifying key matches
	if err = h.validateReq(crt, verKey, verChain, maxChain, config); err != nil {
		h.logDropReq(saddr, req, err)
		return
	}
	// Issue certificate chain
	newChain, err := h.issueChain(ctx, crt, verKey, config)
	if err != nil {
		log.Error("[ReissHandler] Unable to reissue certificate chain", "err", err)
		return
	}
	// Send issued certificate chain
	if err := h.sendRep(ctx, saddr, newChain, r.ID); err != nil {
		log.Error("[ReissHandler] Unable to send reissued certificate chain", "addr", saddr,
			"req", req, "err", err)
	}
}

// validateSign validates that the signer matches the requester and returns the
// certificate chain used when verifying the signature.
func (h *ReissHandler) validateSign(ctx context.Context, addr *snet.Addr, signed *ctrl.SignedPld,
	config *conf.Conf) (*cert.Chain, error) {

	if signed.Sign == nil {
		return nil, common.NewBasicError("Sign is nil", nil)
	}
	src, err := ctrl.NewSignSrcDefFromRaw(signed.Sign.Src)
	if err != nil {
		return nil, err
	}
	verChain, err := ctrl.GetChainForSign(ctx, src, config.Store)
	if err != nil {
		return nil, err
	}
	if signed.Sign.Type.String() != verChain.Leaf.SignAlgorithm {
		return nil, common.NewBasicError("Invalid sign type", nil,
			"expected", verChain.Leaf.SignAlgorithm, "actual", signed.Sign.Type)
	}
	// Verify that the requester matches the signer
	if !verChain.Leaf.Subject.Eq(addr.IA) {
		return nil, common.NewBasicError("Origin AS does not match signer", nil,
			"signer", verChain.Leaf.Subject, "origin", addr.IA)
	}
	return verChain, nil
}

// validateReq validates the requested certificate. Additionally, it validates that
// the request was verified with the same verifying key as in the customer mapping.
func (h *ReissHandler) validateReq(c *cert.Certificate, vKey common.RawBytes,
	vChain, maxChain *cert.Chain, config *conf.Conf) error {

	if !c.Subject.Eq(vChain.Leaf.Subject) {
		return common.NewBasicError("Requester does not match subject", nil, "ia",
			vChain.Leaf.Subject, "sub", c.Subject)
	}
	if maxChain.Leaf.Version+1 != c.Version {
		return common.NewBasicError("Invalid version", nil, "expected", maxChain.Leaf.Version,
			"actual", c.Version)
	}
	if !c.Issuer.Eq(config.PublicAddr.IA) {
		return common.NewBasicError("Requested Issuer is not this AS", nil, "iss",
			c.Issuer, "expected", config.PublicAddr.IA)
	}
	if c.CanIssue {
		return common.NewBasicError("CanIssue not allowed to be true", nil)
	}
	if !bytes.Equal(vKey, vChain.Leaf.SubjectSignKey) {
		return common.NewBasicError("Request signed with wrong signing key", nil)
	}
	return nil
}

// issueChain creates a certificate chain for the certificate and adds it to the
// trust store.
func (h *ReissHandler) issueChain(ctx context.Context, c *cert.Certificate, vKey common.RawBytes,
	config *conf.Conf) (*cert.Chain, error) {

	issCert, err := getIssuerCert(config)
	if err != nil {
		return nil, err
	}
	chain := &cert.Chain{Leaf: c.Copy(), Issuer: issCert}
	chain.Leaf.CanIssue = false
	chain.Leaf.TRCVersion = chain.Issuer.TRCVersion
	chain.Leaf.IssuingTime = util.TimeToSecs(time.Now())
	chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + cert.DefaultLeafCertValidity
	// Leaf certificate must expire before issuer certificate
	if chain.Issuer.ExpirationTime < chain.Leaf.ExpirationTime {
		chain.Leaf.ExpirationTime = chain.Issuer.ExpirationTime
	}
	if err = chain.Leaf.Sign(config.GetIssSigningKey(), chain.Issuer.SignAlgorithm); err != nil {
		return nil, err
	}
	err = chain.Leaf.Verify(c.Subject, issCert.SubjectSignKey, issCert.SignAlgorithm)
	if err != nil {
		return nil, err
	}
	// Set verifying key.
	err = config.Customers.SetVerifyingKey(c.Subject, c.Version, c.SubjectSignKey, vKey)
	if err != nil {
		return nil, err
	}
	if _, err = config.TrustDB.InsertChain(chain); err != nil {
		log.Error("[ReissHandler] Unable to write reissued certificate chain to disk", "err", err)
		return nil, err
	}
	return chain, nil
}

func (h *ReissHandler) sendRep(ctx context.Context, addr net.Addr, chain *cert.Chain,
	id uint64) error {

	raw, err := chain.Compress()
	if err != nil {
		return err
	}
	msger, ok := infra.MessengerFromContext(ctx)
	if !ok {
		return common.NewBasicError("[ReissHandler] Unable to service request, no messenger found",
			nil)
	}
	return msger.SendChainIssueReply(ctx, &cert_mgmt.ChainIssRep{RawChain: raw}, addr, id)
}

func (h *ReissHandler) logDropReq(addr net.Addr, req *cert_mgmt.ChainIssReq, err error) {
	log.Error("[ReissHandler] Dropping certificate reissue request", "addr", addr, "req", req,
		"err", err)
}

func (h *ReissHandler) logDropRep(addr net.Addr, rep *cert_mgmt.ChainIssRep, err error) {
	log.Error("[ReissHandler] Dropping certificate reissue reply", "addr", addr, "rep", rep,
		"err", err)
}
