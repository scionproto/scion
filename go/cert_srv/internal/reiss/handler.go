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

package reiss

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/lib/addr"
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

	KeyChanged   = "Verifying key has changed in the meantime"
	NotACustomer = "ISD-AS not in customer mapping"
)

// Handler handles certificate chain reissue requests.
//
// Reissue requests are sent by non-issuer ASes to issuer ASes. The request
// needs to be signed with the private key associated with the newest verifying
// key in the customer mapping. Certificate chains are issued automatically by
// the issuer ASes.
type Handler struct {
	State *csconfig.State
	IA    addr.IA
}

func (h *Handler) Handle(r *infra.Request) {
	addr := r.Peer.(*snet.Addr)
	req := r.Message.(*cert_mgmt.ChainIssReq)
	if err := h.handle(r, addr, req); err != nil {
		log.Error("[ReissHandler] Dropping certificate reissue request",
			"addr", addr, "req", req, "err", err)
	}
}

// handle handles certificate chain reissue requests. If the requested
// certificate chain is already present, the existing certificate chain is
// resent. Otherwise, a new certificate chain is issued.
func (h *Handler) handle(r *infra.Request, addr *snet.Addr, req *cert_mgmt.ChainIssReq) error {
	ctx, cancelF := context.WithTimeout(r.Context(), HandlerTimeout)
	defer cancelF()
	signed := r.FullMessage.(*ctrl.SignedPld)
	log.Trace("[ReissHandler] Received certificate reissue request", "addr", addr, "req", req)
	// Validate the request was correctly signed by the requester
	verChain, err := h.validateSign(ctx, addr, signed)
	if err != nil {
		return common.NewBasicError("Unable to validate chain", err)
	}
	// Parse the requested certificate
	crt, err := req.Cert()
	if err != nil {
		return common.NewBasicError("Unable to parse requested certificate", err)
	}
	// Respond with max chain for outdated requests.
	maxChain, err := h.State.Store.GetChain(ctx, verChain.Leaf.Subject, scrypto.LatestVer)
	if err != nil {
		return common.NewBasicError("Unable to fetch max chain", err)
	}
	if maxChain != nil && crt.Version <= maxChain.Leaf.Version {
		log.Info("[ReissHandler] Resending certificate chain", "addr", addr, "req", req)
		return h.sendRep(ctx, addr, maxChain, r.ID)
	}
	// Get the verifying key from the customer mapping
	verKey, verVersion, err := h.getVerifyingKey(ctx, addr.IA)
	if err != nil {
		return common.NewBasicError("Unable to get verifying key", err)
	}
	// Verify request and check the verifying key matches
	if err = h.validateReq(crt, verKey, verChain, maxChain); err != nil {
		return common.NewBasicError("Unable to verify request", err)
	}
	// Issue certificate chain
	newChain, err := h.issueChain(ctx, crt, verKey, verVersion)
	if err != nil {
		return common.NewBasicError("Unable to reissue certificate chain", err)
	}
	// Send issued certificate chain
	if err := h.sendRep(ctx, addr, newChain, r.ID); err != nil {
		return common.NewBasicError("Unable to send reissued certificate chain", err)
	}
	return nil
}

// validateSign validates that the signer matches the requester and returns the
// certificate chain used when verifying the signature.
func (h *Handler) validateSign(ctx context.Context, addr *snet.Addr,
	signed *ctrl.SignedPld) (*cert.Chain, error) {

	if signed.Sign == nil {
		return nil, common.NewBasicError("Sign is nil", nil)
	}
	src, err := ctrl.NewSignSrcDefFromRaw(signed.Sign.Src)
	if err != nil {
		return nil, err
	}
	verChain, err := ctrl.GetChainForSign(ctx, src, h.State.Store)
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
func (h *Handler) validateReq(c *cert.Certificate, vKey common.RawBytes,
	vChain, maxChain *cert.Chain) error {

	if !c.Subject.Eq(vChain.Leaf.Subject) {
		return common.NewBasicError("Requester does not match subject", nil, "ia",
			vChain.Leaf.Subject, "sub", c.Subject)
	}
	if maxChain.Leaf.Version+1 != c.Version {
		return common.NewBasicError("Invalid version", nil, "expected", maxChain.Leaf.Version+1,
			"actual", c.Version)
	}
	if !c.Issuer.Eq(h.IA) {
		return common.NewBasicError("Requested Issuer is not this AS", nil, "iss",
			c.Issuer, "expected", h.IA)
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
func (h *Handler) issueChain(ctx context.Context, c *cert.Certificate,
	vKey common.RawBytes, verVersion uint64) (*cert.Chain, error) {

	issCert, err := h.getIssuerCert(ctx)
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
	if err = chain.Leaf.Sign(h.State.GetIssSigningKey(), chain.Issuer.SignAlgorithm); err != nil {
		return nil, err
	}
	err = chain.Leaf.Verify(c.Subject, issCert.SubjectSignKey, issCert.SignAlgorithm)
	if err != nil {
		return nil, err
	}
	tx, err := h.State.TrustDB.BeginTransaction(ctx, nil)
	if err != nil {
		return nil, common.NewBasicError("Failed to create transaction", err)
	}
	// Set verifying key.
	err = tx.InsertCustKey(ctx, c.Subject, c.Version, c.SubjectSignKey, verVersion)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	var n int64
	if n, err = tx.InsertChain(ctx, chain); err != nil {
		tx.Rollback()
		log.Error("[ReissHandler] Unable to write reissued certificate chain to disk", "err", err)
		return nil, err
	}
	if n == 0 {
		tx.Rollback()
		return nil, common.NewBasicError("Chain already in DB", nil, "chain", chain)
	}
	if err = tx.Commit(); err != nil {
		return nil, common.NewBasicError("Failed to commit transaction", err)
	}
	return chain, nil
}

func (h *Handler) sendRep(ctx context.Context, addr net.Addr, chain *cert.Chain,
	id uint64) error {

	raw, err := chain.Compress()
	if err != nil {
		return err
	}
	msger, ok := infra.MessengerFromContext(ctx)
	if !ok {
		return common.NewBasicError("Unable to send reply, no messenger found", nil)
	}
	log.Trace("[ReissHandler] Sending reissued certificate chain",
		"chain", chain, "addr", addr)
	return msger.SendChainIssueReply(ctx, &cert_mgmt.ChainIssRep{RawChain: raw}, addr, id)
}

func (h *Handler) getIssuerCert(ctx context.Context) (*cert.Certificate, error) {
	issCrt, err := h.State.TrustDB.GetIssCertMaxVersion(ctx, h.IA)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil, "ia", h.IA)
	}
	return issCrt, nil
}

// getVerifyingKey returns the verifying key from the requested AS and nil if it is in the mapping.
// Otherwise, nil and an error.
func (h *Handler) getVerifyingKey(ctx context.Context,
	ia addr.IA) (common.RawBytes, uint64, error) {

	k, v, err := h.State.TrustDB.GetCustKey(ctx, ia)
	if err != nil {
		return nil, 0, err
	}
	if k == nil {
		return nil, 0, common.NewBasicError(NotACustomer, nil, "ISD-AS", ia)
	}
	return k, v, nil
}
