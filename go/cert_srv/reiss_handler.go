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
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/cert_srv/conf"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
)

// ReissHandler handles certificate chain reissue requests and replies.
//
// Reissue requests sent by non-issuer ASes to issuer ASes. The request
// needs to be signed with the private key associated with the newest
// verifying key in the customer mapping. Certificate chains are issued
// automatically by the issuer ASes.
type ReissHandler struct {
	conn *snet.Conn
}

func NewReissHandler(conn *snet.Conn) *ReissHandler {
	return &ReissHandler{conn: conn}
}

// HandleReq handles certificate chain reissue requests. If the requested
// certificate chain is already present, the existing certificate chain is
// resent. Otherwise, a new certificate chain is issued.
func (h *ReissHandler) HandleReq(addr *snet.Addr, req *cert_mgmt.ChainIssReq,
	signed *ctrl.SignedPld, config *conf.Conf) {

	log.Info("Received certificate reissue request", "addr", addr, "req", req)
	if !config.Topo.Core {
		log.Warn("Received certificate reissue request as non-issuer AS",
			"addr", addr, "req", req)
		return
	}
	// Validate the request was correctly signed by the requester
	verChain, err := h.validateSign(addr, signed, config)
	if err != nil {
		h.logDropReq(addr, req, err)
		return
	}
	// Parse the requested certificate
	crt, err := req.Cert()
	if err != nil {
		h.logDropReq(addr, req, err)
		return
	}
	// Respond with max chain for outdated requests.
	maxChain := config.Store.GetNewestChain(verChain.Leaf.Subject)
	if maxChain != nil && crt.Version <= maxChain.Leaf.Version {
		log.Info("Resending certificate chain", "addr", addr, "req", req)
		if err = h.sendRep(addr, maxChain, config); err != nil {
			log.Error("Unable to resend certificate chain", "addr", addr,
				"req", req, "err", err)
		}
		return
	}
	// Get the verifying key from the customer mapping
	verKey, err := config.Customers.GetVerifyingKey(addr.IA)
	if err != nil {
		h.logDropReq(addr, req, err)
		return
	}
	// Verify request and check the verifying key matches
	if err = h.validateReq(crt, verKey, verChain, maxChain, config); err != nil {
		h.logDropReq(addr, req, err)
		return
	}
	// Issue certificate chain
	newChain, err := h.issueChain(crt, verKey, config)
	if err != nil {
		log.Error("Unable to reissue certificate chain", "err", err)
		return
	}
	// Send issued certificate chain
	if err = h.sendRep(addr, newChain, config); err != nil {
		log.Error("Unable to send reissued certificate chain", "addr", addr,
			"req", req, "err", err)
	}
}

// validateSign validates that the signer matches the requester and returns the
// certificate chain used when verifying the signature.
func (h *ReissHandler) validateSign(addr *snet.Addr, signed *ctrl.SignedPld,
	config *conf.Conf) (*cert.Chain, error) {

	if signed.Sign == nil {
		return nil, common.NewBasicError("Sign is nil", nil)
	}
	src, err := ctrl.NewSignSrcDefFromRaw(signed.Sign.Src)
	if err != nil {
		return nil, err
	}
	verChain, err := getChainForSign(src)
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
func (h *ReissHandler) issueChain(c *cert.Certificate, vKey common.RawBytes,
	config *conf.Conf) (*cert.Chain, error) {

	issCert, err := getIssuerCert(config)
	if err != nil {
		return nil, err
	}
	chain := &cert.Chain{Leaf: c.Copy(), Issuer: issCert}
	chain.Leaf.CanIssue = false
	chain.Leaf.TRCVersion = chain.Issuer.TRCVersion
	chain.Leaf.IssuingTime = uint32(time.Now().Unix())
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
	if err = config.Store.AddChain(chain, true); err != nil {
		log.Error("Unable to write reissued certificate chain to disk", "err", err)
	}
	return chain, nil
}

// sendRep creates a certificate chain reply and sends it to the requester.
func (h *ReissHandler) sendRep(addr *snet.Addr, chain *cert.Chain, config *conf.Conf) error {
	raw, err := chain.Compress()
	if err != nil {
		return err
	}
	cpld, err := ctrl.NewCertMgmtPld(&cert_mgmt.ChainIssRep{RawChain: raw}, nil, nil)
	if err != nil {
		return err
	}
	log.Info("Send reissued certificate chain", "chain", chain, "addr", addr)
	return SendSignedPayload(h.conn, cpld, addr, config)
}

// HandleRep handles certificate chain reissue replies.
func (h *ReissHandler) HandleRep(addr *snet.Addr, rep *cert_mgmt.ChainIssRep, config *conf.Conf) {
	log.Info("Received certificate reissue reply", "addr", addr, "rep", rep)
	if config.Topo.Core {
		log.Warn("Received certificate reissue reply as issuer AS", "addr", addr, "req", rep)
		return
	}
	chain, err := rep.Chain()
	if err != nil {
		h.logDropRep(addr, rep, err)
		return
	}
	if err = h.validateRep(chain, config); err != nil {
		h.logDropRep(addr, rep, err)
		return
	}
	if err = config.Store.AddChain(chain, true); err != nil {
		log.Error("Unable to write reissued certificate chain to disk", "chain", chain, "err", err)
		return
	}
	sign, err := CreateSign(config.PublicAddr.IA, config.Store)
	if err != nil {
		log.Error("Unable to set new signer", "err", err)
		return
	}
	config.SetSigner(ctrl.NewBasicSigner(sign, config.GetSigningKey()))
}

// validateRep validates that the received certificate chain can be added to the trust store.
func (h *ReissHandler) validateRep(chain *cert.Chain, config *conf.Conf) error {
	verKey := common.RawBytes(ed25519.PrivateKey(
		config.GetSigningKey()).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		return common.NewBasicError("Invalid SubjectSignKey", nil, "expected",
			verKey, "actual", chain.Leaf.SubjectSignKey)
	}
	// FIXME(roosd): validate SubjectEncKey
	issuer := config.Store.GetNewestChain(config.PublicAddr.IA).Leaf.Issuer
	if !chain.Leaf.Issuer.Eq(issuer) {
		return common.NewBasicError("Invalid Issuer", nil, "expected",
			issuer, "actual", chain.Leaf.Issuer)
	}
	return config.Store.VerifyChain(config.PublicAddr.IA, chain)
}

func (h *ReissHandler) logDropReq(addr *snet.Addr, req *cert_mgmt.ChainIssReq, err error) {
	log.Error("Dropping certificate reissue request", "addr", addr, "req", req, "err", err)
}

func (h *ReissHandler) logDropRep(addr *snet.Addr, rep *cert_mgmt.ChainIssRep, err error) {
	log.Error("Dropping certificate reissue reply", "addr", addr, "rep", rep, "err", err)
}
