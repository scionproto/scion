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

package main

import (
	"bytes"
	"context"
	"net"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/cert_srv/conf"
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

const (
	DefaultReissTimeout = 5 * time.Second
)

// SelfIssuer periodically issues self-signed certificate chains
// on an issuer AS before the old one expires.
type SelfIssuer struct {
	// msger is used to propagate key updates to the messenger, and not for network traffic
	msger *messenger.Messenger
}

// NewSelfIssuer creates a new periodic certificate chain reissuer for the
// local AS. Argument msger is only used to propagate key changes, and not for
// network traffic.
func NewSelfIssuer(msger *messenger.Messenger) *SelfIssuer {
	return &SelfIssuer{
		msger: msger,
	}
}

// Run periodically issues certificate chains for the local AS.
func (s *SelfIssuer) Run() {
	if !conf.Get().Topo.Core {
		log.Info("[SelfIssuer] Stopping SelfIssuer on non-issuer CS")
		return
	}
	for {
		var err error
		now := time.Now()
		config := conf.Get()
		issCrt, err := getIssuerCert(config)
		if err != nil {
			log.Crit("[SelfIssuer] Unable to get issuer certificate", "err", err)
			break
		}
		chain, err := config.Store.GetChain(context.Background(), config.PublicAddr.IA,
			scrypto.LatestVer)
		if err != nil {
			log.Crit("[SelfIssuer] Unable to get certificate", "err", err)
			break
		}
		leafCrt := chain.Leaf
		iSleep := time.Unix(int64(issCrt.ExpirationTime), 0).Sub(now) - config.IssuerReissTime
		lSleep := time.Unix(int64(leafCrt.ExpirationTime), 0).Sub(now) - config.LeafReissTime
		if lSleep > 0 && iSleep > 0 {
			if iSleep < lSleep {
				time.Sleep(iSleep)
			} else {
				time.Sleep(lSleep)
			}
			continue
		}
		if iSleep > 0 {
			if err = s.createLeafCert(leafCrt, config); err != nil {
				log.Error("[SelfIssuer] Unable to issue certificate chain", "err", err)
				time.Sleep(config.ReissRate)
				continue
			}
		} else {
			if err = s.createIssuerCert(config); err != nil {
				log.Error("[SelfIssuer] Unable to create issuer certificate", "err", err)
				time.Sleep(config.ReissRate)
				continue
			}
		}
	}
}

// createLeafCert creates a leaf certificate.
func (s *SelfIssuer) createLeafCert(leaf *cert.Certificate, config *conf.Conf) error {
	issCrt, err := getIssuerCert(config)
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
	if err := chain.Leaf.Sign(config.GetIssSigningKey(), issCrt.SignAlgorithm); err != nil {
		return common.NewBasicError("Unable to sign leaf certificate", err, "chain", chain)
	}
	if err := trust.VerifyChain(config.PublicAddr.IA, chain, config.Store); err != nil {
		return common.NewBasicError("Unable to verify chain", err, "chain", chain)
	}
	if _, err := config.TrustDB.InsertChain(chain); err != nil {
		return common.NewBasicError("Unable to write certificate chain", err, "chain", chain)
	}
	log.Info("[SelfIssuer] Created certificate chain", "chain", chain)
	sign, err := trust.CreateSign(config.PublicAddr.IA, config.Store)
	if err != nil {
		log.Error("[SelfIssuer] Unable to set create new sign", "err", err)
	}
	signer := ctrl.NewBasicSigner(sign, config.GetSigningKey())
	config.SetSigner(signer)
	s.msger.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueReply})
	return nil
}

// createIssuerCert creates an issuer certificate.
func (s *SelfIssuer) createIssuerCert(config *conf.Conf) error {
	crt, err := getIssuerCert(config)
	if err != nil {
		return err
	}
	crt.Version += 1
	crt.IssuingTime = util.TimeToSecs(time.Now())
	crt.CanIssue = true
	crt.ExpirationTime = crt.IssuingTime + cert.DefaultIssuerCertValidity
	coreAS, err := s.getCoreASEntry(config)
	if err != nil {
		return common.NewBasicError("Unable to get core AS entry", err, "cert", crt)
	}
	if err = crt.Sign(config.GetOnRootKey(), coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Unable to sign issuer certificate", err, "cert", crt)
	}
	if err = crt.Verify(crt.Issuer, coreAS.OnlineKey, coreAS.OnlineKeyAlg); err != nil {
		return common.NewBasicError("Invalid issuer certificate signature", err, "cert", crt)
	}
	if err = setIssuerCert(crt, config); err != nil {
		return common.NewBasicError("Unable to store issuer certificate", err, "cert", crt)
	}
	log.Info("[SelfIssuer] Created issuer certificate", "cert", crt)
	return nil
}

func (s *SelfIssuer) getCoreASEntry(config *conf.Conf) (*trc.CoreAS, error) {
	maxTrc, err := config.Store.GetTRC(context.Background(), config.PublicAddr.IA.I,
		scrypto.LatestVer)
	if err != nil {
		return nil, common.NewBasicError("Unable to find local TRC", err)
	}
	coreAS := maxTrc.CoreASes[config.PublicAddr.IA]
	if coreAS == nil {
		return nil, common.NewBasicError("Local AS is not a core AS in the max TRC",
			nil, "maxTrc", maxTrc)
	}
	return coreAS, nil
}

func getIssuerCert(config *conf.Conf) (*cert.Certificate, error) {
	issCrt, err := config.TrustDB.GetIssCertMaxVersion(config.PublicAddr.IA)
	if err != nil {
		return nil, err
	}
	if issCrt == nil {
		return nil, common.NewBasicError("Issuer certificate not found", nil,
			"ia", config.PublicAddr.IA)
	}
	return issCrt, nil
}

func setIssuerCert(crt *cert.Certificate, config *conf.Conf) error {
	affected, err := config.TrustDB.InsertIssCert(crt)
	if err != nil {
		return err
	}
	if affected == 0 {
		return common.NewBasicError("Issuer certificate already exists", nil, "cert", crt)
	}
	return nil
}

// ReissRequester periodically requests reissued certificate chains before
// expiration of the currently active certificate chain.
type ReissRequester struct {
	msger *messenger.Messenger
	stop  chan struct{}
}

func NewReissRequester(msger *messenger.Messenger) *ReissRequester {
	return &ReissRequester{
		msger: msger,
		stop:  make(chan struct{}),
	}
}

// Run periodically requests reissued certificate chains from the issuer AS.
func (r *ReissRequester) Run() {
	if conf.Get().Topo.Core {
		log.Info("[ReissRequester] Stopping ReissRequester on issuer CS")
		return
	}
	for {
		select {
		case <-r.stop:
			return
		default:
			config := conf.Get()
			chain, err := config.Store.GetChain(context.Background(), config.PublicAddr.IA,
				scrypto.LatestVer)
			if err != nil {
				panic(err)
			}
			now := time.Now()
			exp := util.SecsToTime(chain.Leaf.ExpirationTime)
			diff := exp.Sub(now)
			if diff < 0 {
				log.Error("[ReissRequester] Certificate expired without being reissued",
					"ExpirationTime", util.TimeToString(exp), "now", util.TimeToString(now))
				return
			}
			if sleep := diff - config.LeafReissTime; sleep > 0 {
				time.Sleep(sleep)
				continue
			}

			ctx, cancelF := context.WithTimeout(context.Background(), DefaultReissTimeout)
			go r.sendReq(ctx, cancelF, chain, config)
			time.Sleep(config.ReissRate)
		}
	}
}

// sendReq creates and sends a certificate chain reissue request based on the newest
// currently active certificate chain.
func (r *ReissRequester) sendReq(ctx context.Context, cancelF context.CancelFunc,
	chain *cert.Chain, config *conf.Conf) error {

	defer cancelF()
	c := chain.Leaf.Copy()
	c.IssuingTime = util.TimeToSecs(time.Now())
	c.ExpirationTime = c.IssuingTime + (chain.Leaf.ExpirationTime - chain.Leaf.IssuingTime)
	c.Version += 1
	if err := c.Sign(config.GetSigningKey(), chain.Leaf.SignAlgorithm); err != nil {
		return err
	}
	raw, err := c.JSON(false)
	if err != nil {
		return err
	}
	request := &cert_mgmt.ChainIssReq{RawCert: raw}
	a := &snet.Addr{IA: c.Issuer, Host: &addr.AppAddr{L3: addr.SvcCS}}
	rep, err := r.msger.RequestChainIssue(ctx, request, a, messenger.NextId())
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
	if err = r.validateRep(ctx, repChain, config); err != nil {
		r.logDropRep(a, rep, err)
		return nil
	}
	if _, err = config.TrustDB.InsertChain(repChain); err != nil {
		log.Error("[ReissRequester] Unable to write reissued certificate chain to disk",
			"chain", repChain, "err", err)
		return nil
	}

	sign, err := trust.CreateSign(config.PublicAddr.IA, config.Store)
	if err != nil {
		return common.NewBasicError("Unable to set new signer", err)
	}
	signer := ctrl.NewBasicSigner(sign, config.GetSigningKey())
	config.SetSigner(signer)
	r.msger.UpdateSigner(signer, []infra.MessageType{infra.ChainIssueRequest})
	return nil
}

// validateRep validates that the received certificate chain can be added to the trust store.
func (r *ReissRequester) validateRep(ctx context.Context,
	chain *cert.Chain, config *conf.Conf) error {

	verKey := common.RawBytes(ed25519.PrivateKey(
		config.GetSigningKey()).Public().(ed25519.PublicKey))
	if !bytes.Equal(chain.Leaf.SubjectSignKey, verKey) {
		return common.NewBasicError("Invalid SubjectSignKey", nil, "expected",
			verKey, "actual", chain.Leaf.SubjectSignKey)
	}
	// FIXME(roosd): validate SubjectEncKey
	chain, err := config.Store.GetChain(ctx, config.PublicAddr.IA, scrypto.LatestVer)
	if err != nil {
		return err
	}
	issuer := chain.Leaf.Issuer
	if !chain.Leaf.Issuer.Eq(issuer) {
		return common.NewBasicError("Invalid Issuer", nil, "expected",
			issuer, "actual", chain.Leaf.Issuer)
	}
	return trust.VerifyChain(config.PublicAddr.IA, chain, config.Store)
}

func (r *ReissRequester) logDropRep(addr net.Addr, rep *cert_mgmt.ChainIssRep, err error) {
	log.Error("[ReissRequester] Dropping certificate reissue reply", "addr", addr, "rep", rep,
		"err", err)
}

// Close terminates the ReissRequester.
func (r *ReissRequester) Close() {
	close(r.stop)
}
