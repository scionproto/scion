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

package reiss

import (
	"bytes"
	"context"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/cert_srv/internal/csconfig"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

var _ periodic.Task = (*Self)(nil)

// Self periodically issues self-signed certificate chains
// on an issuer AS before the old one expires.
type Self struct {
	// Msgr is used to propagate key updates to the messenger, and not for network traffic
	Msgr     *messenger.Messenger
	State    *csconfig.State
	IA       addr.IA
	IssTime  time.Duration
	LeafTime time.Duration
}

// Run issues certificate chains for the local AS.
func (s *Self) Run(ctx context.Context) {
	if err := s.run(ctx); err != nil {
		log.Crit("[reiss.Self] Unable to self issue", "err", err)
	}
}

func (s *Self) run(ctx context.Context) error {
	issCrt, err := s.getIssuerCert()
	if err != nil {
		return common.NewBasicError("Unable to get issuer certificate", err)
	}
	chain, err := s.State.Store.GetChain(context.Background(), s.IA, scrypto.LatestVer)
	if err != nil {
		return common.NewBasicError("Unable to get certificate chain", err)
	}
	now := time.Now()
	iSleep := time.Unix(int64(issCrt.ExpirationTime), 0).Sub(now) - s.IssTime
	lSleep := time.Unix(int64(chain.Leaf.ExpirationTime), 0).Sub(now) - s.LeafTime
	if lSleep > 0 && iSleep > 0 {
		return nil
	}
	if iSleep <= 0 {
		// The issuer certificated needs to be updated.
		if err = s.createIssuerCert(issCrt); err != nil {
			return common.NewBasicError("Unable to create issuer certificate", err)
		}
	}
	if lSleep <= 0 {
		if err = s.createLeafCert(chain.Leaf); err != nil {
			return common.NewBasicError("Unable to issue certificate chain", err)
		}
	}
	return nil
}

// createLeafCert creates a leaf certificate.
func (s *Self) createLeafCert(leaf *cert.Certificate) error {
	issCrt, err := s.getIssuerCert()
	if err != nil {
		return common.NewBasicError("Unable to get issuer certificate", err)
	}
	chain := &cert.Chain{Leaf: leaf.Copy(), Issuer: issCrt}
	chain.Leaf.Version += 1
	chain.Leaf.IssuingTime = util.TimeToSecs(time.Now())
	chain.Leaf.CanIssue = false
	chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + cert.DefaultLeafCertValidity
	if chain.Issuer.ExpirationTime < chain.Leaf.ExpirationTime {
		chain.Leaf.ExpirationTime = chain.Issuer.ExpirationTime
	}
	if err := chain.Leaf.Sign(s.State.GetIssSigningKey(), issCrt.SignAlgorithm); err != nil {
		return common.NewBasicError("Unable to sign leaf certificate", err, "chain", chain)
	}
	if err := trust.VerifyChain(s.IA, chain, s.State.Store); err != nil {
		return common.NewBasicError("Unable to verify chain", err, "chain", chain)
	}
	if _, err := s.State.TrustDB.InsertChain(chain); err != nil {
		return common.NewBasicError("Unable to write certificate chain", err, "chain", chain)
	}
	log.Info("[reiss.Self] Created certificate chain", "chain", chain)
	sign, err := trust.CreateSign(s.IA, s.State.Store)
	if err != nil {
		log.Error("[reiss.Self] Unable to set create new sign", "err", err)
	}
	signer := ctrl.NewBasicSigner(sign, s.State.GetSigningKey())
	s.State.SetSigner(signer)
	s.Msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueReply})
	return nil
}

func (s *Self) getIssuerCert() (*cert.Certificate, error) {
	issCrt, err := s.State.TrustDB.GetIssCertMaxVersion(s.IA)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil, "ia", s.IA)
	}
	return issCrt, nil
}

// createIssuerCert creates an issuer certificate.
func (s *Self) createIssuerCert(crt *cert.Certificate) error {
	crt = crt.Copy()
	crt.Version += 1
	crt.IssuingTime = util.TimeToSecs(time.Now())
	crt.CanIssue = true
	crt.ExpirationTime = crt.IssuingTime + cert.DefaultIssuerCertValidity
	coreAS, err := s.getCoreASEntry()
	if err != nil {
		return common.NewBasicError("Unable to get core AS entry", err, "cert", crt)
	}
	if err = crt.Sign(s.State.GetOnRootKey(), coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Unable to sign issuer certificate", err, "cert", crt)
	}
	if err = crt.Verify(crt.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Invalid issuer certificate signature", err, "cert", crt)
	}
	if err = s.setIssuerCert(crt); err != nil {
		return common.NewBasicError("Unable to store issuer certificate", err, "cert", crt)
	}
	log.Info("[reiss.Self] Created issuer certificate", "cert", crt)
	return nil
}

func (s *Self) getCoreASEntry() (*trc.CoreAS, error) {
	maxTrc, err := s.State.Store.GetTRC(context.Background(), s.IA.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to find local TRC", err)
	}
	coreAS := maxTrc.CoreASes[s.IA]
	if coreAS == nil {
		return nil, common.NewBasicError("Local AS is not a core AS in the max TRC",
			nil, "maxTrc", maxTrc)
	}
	return coreAS, nil
}

func (s *Self) setIssuerCert(crt *cert.Certificate) error {
	affected, err := s.State.TrustDB.InsertIssCert(crt)
	if err != nil {
		return err
	}
	if affected == 0 {
		return common.NewBasicError("Issuer certificate already exists", nil, "cert", crt)
	}
	return nil
}

var _ periodic.Task = (*Requester)(nil)

// Requester requests reissued certificate chains before
// expiration of the currently active certificate chain.
type Requester struct {
	Msgr     *messenger.Messenger
	State    *csconfig.State
	IA       addr.IA
	LeafTime time.Duration
}

// Run requests reissued certificate chains from the issuer AS.
func (r *Requester) Run(ctx context.Context) {
	crit, err := r.run(ctx)
	switch {
	case crit && err != nil:
		log.Crit("[reiss.Requester] Unable to get reissued certificate chain", "err", err)
	case err != nil:
		log.Error("[reiss.Requester] Unable to get reissued certificate chain", "err", err)
	}
}

func (r *Requester) run(ctx context.Context) (bool, error) {
	chain, err := r.State.Store.GetChain(ctx, r.IA, scrypto.LatestVer)
	if err != nil {
		return true, common.NewBasicError("Unable to get local certificate chain", err)
	}
	exp := util.SecsToTime(chain.Leaf.ExpirationTime)
	now := time.Now()
	if now.After(exp) {
		return true, common.NewBasicError("Certificate expired without being reissued", nil,
			"chain", chain, "expTime", util.TimeToString(exp), "now", util.TimeToString(now))
	}
	if now.Add(r.LeafTime).Before(exp) {
		return false, nil
	}
	return r.sendReq(ctx, chain)
}

// sendReq creates and sends a certificate chain reissue request based on the newest
// currently active certificate chain.
func (r *Requester) sendReq(ctx context.Context, chain *cert.Chain) (bool, error) {
	c := chain.Leaf.Copy()
	c.IssuingTime = util.TimeToSecs(time.Now())
	c.ExpirationTime = c.IssuingTime + (chain.Leaf.ExpirationTime - chain.Leaf.IssuingTime)
	c.Version += 1
	if err := c.Sign(r.State.GetSigningKey(), chain.Leaf.SignAlgorithm); err != nil {
		return true, common.NewBasicError("Unable to sign certificate", err)
	}
	raw, err := c.JSON(false)
	if err != nil {
		return false, common.NewBasicError("Unable to pack certificate", err)
	}
	req := &cert_mgmt.ChainIssReq{RawCert: raw}
	a := &snet.Addr{IA: c.Issuer, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	rep, err := r.Msgr.RequestChainIssue(ctx, req, a, messenger.NextId())
	if err != nil {
		return false, common.NewBasicError("Unable to request reissued certificate chain", err)
	}
	log.Trace("[reiss.Requester] Received certificate reissue reply", "addr", a, "rep", rep)
	if crit, err := r.handleRep(ctx, rep); err != nil {
		return crit, common.NewBasicError("Unable to handle reply", err, "addr", a, "rep", rep)
	}
	return false, nil
}

func (r *Requester) handleRep(ctx context.Context, rep *cert_mgmt.ChainIssRep) (bool, error) {
	chain, err := rep.Chain()
	if err != nil {
		return false, common.NewBasicError("Unable to parse chain", err)
	}
	if err = r.validateRep(ctx, chain); err != nil {
		return true, common.NewBasicError("Unable to validate chain", err, "chain", chain)
	}
	if _, err = r.State.TrustDB.InsertChain(chain); err != nil {
		return true, common.NewBasicError("Unable to insert reissued certificate chain in TrustDB",
			err, "chain", chain)
	}
	sign, err := trust.CreateSign(r.IA, r.State.Store)
	if err != nil {
		return true, common.NewBasicError("Unable to set new signer", err)
	}
	signer := ctrl.NewBasicSigner(sign, r.State.GetSigningKey())
	r.State.SetSigner(signer)
	r.Msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueRequest})
	log.Info("[reiss.Requester] Updated certificate chain", "chain", chain)
	return false, nil
}

// validateRep validates that the received certificate chain can be added to the trust store.
func (r *Requester) validateRep(ctx context.Context, chain *cert.Chain) error {
	verKey := common.RawBytes(ed25519.PrivateKey(
		r.State.GetSigningKey()).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		return common.NewBasicError("Invalid SubjectSignKey", nil, "expected",
			verKey, "actual", chain.Leaf.SubjectSignKey)
	}
	// FIXME(roosd): validate SubjectEncKey
	chain, err := r.State.Store.GetChain(ctx, r.IA, scrypto.LatestVer)
	if err != nil {
		return err
	}
	issuer := chain.Leaf.Issuer
	if !chain.Leaf.Issuer.Eq(issuer) {
		return common.NewBasicError("Invalid Issuer", nil, "expected",
			issuer, "actual", chain.Leaf.Issuer)
	}
	return trust.VerifyChain(r.IA, chain, r.State.Store)
}
