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

package periodic

import (
	"bytes"
	"context"
	"net"
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
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/util"
)

// SelfIssuer periodically issues self-signed certificate chains
// on an issuer AS before the old one expires.
type SelfIssuer struct {
	// msgr is used to propagate key updates to the messenger, and not for network traffic
	msgr     *messenger.Messenger
	state    *csconfig.State
	ia       addr.IA
	issTime  time.Duration
	leafTime time.Duration
	rate     time.Duration
	stop     chan struct{}
	stopped  chan struct{}
}

// NewSelfIssuer creates a new periodic certificate chain reissuer for the
// local AS. Argument msgr is only used to propagate key changes, and not for
// network traffic.
func NewSelfIssuer(msgr *messenger.Messenger, state *csconfig.State, ia addr.IA,
	issTime, leafTime, rate time.Duration) *SelfIssuer {

	return &SelfIssuer{
		msgr:     msgr,
		state:    state,
		ia:       ia,
		issTime:  issTime,
		leafTime: leafTime,
		rate:     rate,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// Run periodically issues certificate chains for the local AS.
func (s *SelfIssuer) Run() {
	defer log.LogPanicAndExit()
	defer close(s.stopped)
	ticker := time.NewTicker(s.rate)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			var err error
			issCrt, err := s.getIssuerCert()
			if err != nil {
				log.Crit("[SelfIssuer] Unable to get issuer certificate", "err", err)
				return
			}
			chain, err := s.state.Store.GetChain(context.Background(), s.ia, scrypto.LatestVer)
			if err != nil {
				log.Crit("[SelfIssuer] Unable to get certificate", "err", err)
				return
			}
			leafCrt := chain.Leaf
			iSleep := time.Unix(int64(issCrt.ExpirationTime), 0).Sub(now) - s.issTime
			lSleep := time.Unix(int64(leafCrt.ExpirationTime), 0).Sub(now) - s.leafTime
			if lSleep > 0 && iSleep > 0 {
				// Nothing to do
				break
			}
			if iSleep <= 0 {
				// The issuer certificated needs to be updated.
				if err = s.createIssuerCert(); err != nil {
					log.Error("[SelfIssuer] Unable to create issuer certificate", "err", err)
					break
				}
			}
			if lSleep <= 0 {
				if err = s.createLeafCert(leafCrt); err != nil {
					log.Error("[SelfIssuer] Unable to issue certificate chain", "err", err)
				}
			}
		}
	}
}

// createLeafCert creates a leaf certificate.
func (s *SelfIssuer) createLeafCert(leaf *cert.Certificate) error {
	issCrt, err := s.getIssuerCert()
	if err != nil {
		return nil
	}
	chain := &cert.Chain{Leaf: leaf.Copy(), Issuer: issCrt}
	chain.Leaf.Version += 1
	chain.Leaf.IssuingTime = util.TimeToSecs(time.Now())
	chain.Leaf.CanIssue = false
	chain.Leaf.ExpirationTime = chain.Leaf.IssuingTime + cert.DefaultLeafCertValidity
	if chain.Issuer.ExpirationTime < chain.Leaf.ExpirationTime {
		chain.Leaf.ExpirationTime = chain.Issuer.ExpirationTime
	}
	if err := chain.Leaf.Sign(s.state.GetIssSigningKey(), issCrt.SignAlgorithm); err != nil {
		return common.NewBasicError("Unable to sign leaf certificate", err, "chain", chain)
	}
	if err := trust.VerifyChain(s.ia, chain, s.state.Store); err != nil {
		return common.NewBasicError("Unable to verify chain", err, "chain", chain)
	}
	if _, err := s.state.TrustDB.InsertChain(chain); err != nil {
		return common.NewBasicError("Unable to write certificate chain", err, "chain", chain)
	}
	log.Info("[SelfIssuer] Created certificate chain", "chain", chain)
	sign, err := trust.CreateSign(s.ia, s.state.Store)
	if err != nil {
		log.Error("[SelfIssuer] Unable to set create new sign", "err", err)
	}
	signer := ctrl.NewBasicSigner(sign, s.state.GetSigningKey())
	s.state.SetSigner(signer)
	s.msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueReply})
	return nil
}

// createIssuerCert creates an issuer certificate.
func (s *SelfIssuer) createIssuerCert() error {
	crt, err := s.getIssuerCert()
	if err != nil {
		return err
	}
	crt.Version += 1
	crt.IssuingTime = util.TimeToSecs(time.Now())
	crt.CanIssue = true
	crt.ExpirationTime = crt.IssuingTime + cert.DefaultIssuerCertValidity
	coreAS, err := s.getCoreASEntry()
	if err != nil {
		return common.NewBasicError("Unable to get core AS entry", err, "cert", crt)
	}
	if err = crt.Sign(s.state.GetOnRootKey(), coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Unable to sign issuer certificate", err, "cert", crt)
	}
	if err = crt.Verify(crt.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Invalid issuer certificate signature", err, "cert", crt)
	}
	if err = s.setIssuerCert(crt); err != nil {
		return common.NewBasicError("Unable to store issuer certificate", err, "cert", crt)
	}
	log.Info("[SelfIssuer] Created issuer certificate", "cert", crt)
	return nil
}

func (s *SelfIssuer) getCoreASEntry() (*trc.CoreAS, error) {
	maxTrc, err := s.state.Store.GetTRC(context.Background(), s.ia.I, scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to find local TRC", err)
	}
	coreAS := maxTrc.CoreASes[s.ia]
	if coreAS == nil {
		return nil, common.NewBasicError("Local AS is not a core AS in the max TRC",
			nil, "maxTrc", maxTrc)
	}
	return coreAS, nil
}

func (s *SelfIssuer) getIssuerCert() (*cert.Certificate, error) {
	issCrt, err := s.state.TrustDB.GetIssCertMaxVersion(s.ia)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil, "ia", s.ia)
	}
	return issCrt, nil
}

func (s *SelfIssuer) setIssuerCert(crt *cert.Certificate) error {
	affected, err := s.state.TrustDB.InsertIssCert(crt)
	if err != nil {
		return err
	}
	if affected == 0 {
		return common.NewBasicError("Issuer certificate already exists", nil, "cert", crt)
	}
	return nil
}

// Stop terminates the SelfIssuer.
func (s *SelfIssuer) Stop() {
	close(s.stop)
	<-s.stopped
}

// ReissRequester periodically requests reissued certificate chains before
// expiration of the currently active certificate chain.
type ReissRequester struct {
	msgr     *messenger.Messenger
	state    *csconfig.State
	ia       addr.IA
	leafTime time.Duration
	rate     time.Duration
	timeout  time.Duration
	stop     chan struct{}
	stopped  chan struct{}
}

func NewReissRequester(msgr *messenger.Messenger, state *csconfig.State, ia addr.IA,
	leafTime, rate, timeout time.Duration) *ReissRequester {

	return &ReissRequester{
		msgr:     msgr,
		state:    state,
		ia:       ia,
		leafTime: leafTime,
		rate:     rate,
		timeout:  timeout,
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// Run periodically requests reissued certificate chains from the issuer AS.
func (r *ReissRequester) Run() {
	defer log.LogPanicAndExit()
	defer close(r.stopped)
	ticker := time.NewTicker(r.rate)
	defer ticker.Stop()
	// Context used to cancel outstanding requests
	ctx, cancelF := context.WithCancel(context.Background())
	defer cancelF()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			chain, err := r.state.Store.GetChain(ctx, r.ia, scrypto.LatestVer)
			if err != nil {
				log.Crit("[ReissRequester] Unable to get local certificate chain", "err", err)
				return
			}
			exp := util.SecsToTime(chain.Leaf.ExpirationTime)
			diff := exp.Sub(now)
			if diff < 0 {
				log.Crit("[ReissRequester] Certificate expired without being reissued",
					"ExpirationTime", util.TimeToString(exp), "now", util.TimeToString(now))
				return
			}
			if diff > r.leafTime {
				break
			}
			ctxReq, cancelReq := context.WithTimeout(ctx, r.timeout)
			go r.sendReq(ctxReq, cancelReq, chain)
		}
	}
}

// sendReq creates and sends a certificate chain reissue request based on the newest
// currently active certificate chain.
func (r *ReissRequester) sendReq(ctx context.Context, cancelF context.CancelFunc,
	chain *cert.Chain) error {

	defer cancelF()
	c := chain.Leaf.Copy()
	c.IssuingTime = util.TimeToSecs(time.Now())
	c.ExpirationTime = c.IssuingTime + (chain.Leaf.ExpirationTime - chain.Leaf.IssuingTime)
	c.Version += 1
	if err := c.Sign(r.state.GetSigningKey(), chain.Leaf.SignAlgorithm); err != nil {
		return err
	}
	raw, err := c.JSON(false)
	if err != nil {
		return err
	}
	request := &cert_mgmt.ChainIssReq{RawCert: raw}
	a := &snet.Addr{IA: c.Issuer, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	rep, err := r.msgr.RequestChainIssue(ctx, request, a, messenger.NextId())
	if err != nil {
		log.Warn("[ReissRequester] Unable to request chain issue", "err", err)
		return nil
	}
	log.Info("[ReissRequester] Received certificate reissue reply", "addr", a, "rep", rep)
	repChain, err := rep.Chain()
	if err != nil {
		r.logDropRep(a, rep, err)
		return nil
	}
	if err = r.validateRep(ctx, repChain); err != nil {
		r.logDropRep(a, rep, err)
		return nil
	}
	if _, err = r.state.TrustDB.InsertChain(repChain); err != nil {
		log.Error("[ReissRequester] Unable to write reissued certificate chain to disk",
			"chain", repChain, "err", err)
		return nil
	}

	sign, err := trust.CreateSign(r.ia, r.state.Store)
	if err != nil {
		return common.NewBasicError("Unable to set new signer", err)
	}
	signer := ctrl.NewBasicSigner(sign, r.state.GetSigningKey())
	r.state.SetSigner(signer)
	r.msgr.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueRequest})
	return nil
}

// validateRep validates that the received certificate chain can be added to the trust store.
func (r *ReissRequester) validateRep(ctx context.Context, chain *cert.Chain) error {

	verKey := common.RawBytes(ed25519.PrivateKey(
		r.state.GetSigningKey()).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		return common.NewBasicError("Invalid SubjectSignKey", nil, "expected",
			verKey, "actual", chain.Leaf.SubjectSignKey)
	}
	// FIXME(roosd): validate SubjectEncKey
	chain, err := r.state.Store.GetChain(ctx, r.ia, scrypto.LatestVer)
	if err != nil {
		return err
	}
	issuer := chain.Leaf.Issuer
	if !chain.Leaf.Issuer.Eq(issuer) {
		return common.NewBasicError("Invalid Issuer", nil, "expected",
			issuer, "actual", chain.Leaf.Issuer)
	}
	return trust.VerifyChain(r.ia, chain, r.state.Store)
}

func (r *ReissRequester) logDropRep(addr net.Addr, rep *cert_mgmt.ChainIssRep, err error) {
	log.Error("[ReissRequester] Dropping certificate reissue reply", "addr", addr, "rep", rep,
		"err", err)
}

// Stop terminates the ReissRequester.
func (r *ReissRequester) Stop() {
	close(r.stop)
	<-r.stopped
}
